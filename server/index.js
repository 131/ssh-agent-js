"use strict";

const crypto       = require('crypto');
const EventEmitter = require('events').EventEmitter;

const BigInteger = require('node-jsbn');
const ber        = require('asn1').Ber;
const pemme      = require('nyks/crypto/pemme');
const md5        = require('nyks/crypto/md5');

const PROTOCOL  = require('../lib/protocol.json');
const read      = require('../lib/_read');
const write     = require('../lib/_write');



class Server extends EventEmitter {

  constructor(){
    super();
    this.keys_list  = {};

    this.on("sign", function(){
      console.log("In signing stuffs");
    });
  }

  _new_client (client) {
    var self = this, traffic = new Buffer(0), length;

    var feed = function(buffer) {
      traffic = Buffer.concat([traffic, buffer]);
      console.log("Feeding for traffic", traffic);

      if(traffic.length >= length ) {
        self._parse(client, traffic);
        traffic = new Buffer(0);
        console.log("Cropped traffic is", traffic);
        client.removeListener("data", feed);
        client.once("data", init);
      }
    };

    var init = function(buffer) {
      console.log("Init buffer", buffer);
      if(buffer.length < 4)
        throw "Invalid buffer";
      length = read(buffer, "uint32");
      console.log("New packet, lengh is", length);
      client.on("data", feed);
      feed(buffer.slice(4));
    };

    client.once("data", init);

    client.once("error",function(){
      console.log("Client disconnected");
    });
    client.once("end", function(){
      console.log("No data anymore");
    });
  }


  list_keys_v1 (client, callback) {

    var respondIdentities = function() {
        return write(0, "uint32");
    }

    return this._respond(client, PROTOCOL.SSH_AGENT_RSA_IDENTITIES_ANSWER, respondIdentities, callback);
  }

  list_keys_v2(client, callback) {
    var self = this;
    self.emit("list_keys");

    var respondIdentities = function() {
        var nb = Object.keys(self.keys_list).length;
        var out = [write(nb, "uint32")];

        Object.keys(self.keys_list).forEach(function(key_id){
          var key = self.keys_list[key_id];
          out.push(write(key.public, "string"));
          out.push(write(key.comment, "string"));
        });

        console.log(out);
        return Buffer.concat(out);
    }

    return this._respond(client, PROTOCOL.SSH2_AGENT_IDENTITIES_ANSWER, respondIdentities, callback);
  }

  sign (client, body, callback) {
    var self = this;

    var key_blob = read(body, "string"),
        message  = read(body, "string");
    var fingerprint = md5(key_blob);
    console.log("Request for signing of key", fingerprint);

    var key = self.keys_list[fingerprint];
    var signer = crypto.createSign('RSA-SHA1');
    signer.update(message);
    var sign = signer.sign(pemme(key.private, "RSA PRIVATE KEY"));

    this.emit("sign", {fingerprint:fingerprint, comment:key.comment});

    var respondSigning = function(){
      var blob = write(Buffer.concat([
        write("ssh-rsa", "string"),
        write(sign, "string"),
      ]), "string");
      return blob;
    };

    return this._respond(client, PROTOCOL.SSH2_AGENT_SIGN_RESPONSE, respondSigning, callback);

  }


  add_key (client, body, callback) {
    var algo = read(body, "string").toString('ascii'),
        n = read(body, 'mpint'), 
        e = read(body, 'mpint'),
        d = read(body, 'mpint'),
        coeff = read(body, 'mpint'),
        p = read(body, 'mpint'),
        q = read(body, 'mpint'),
        comment = read(body, 'string');

    var p1 = new BigInteger(p),
        q1 = new BigInteger(q),
        dmp1 = new BigInteger(d),
        dmq1 = new BigInteger(d);

    dmp1 = dmp1.mod(p1.subtract(BigInteger.ONE)).toBuffer();
    dmq1 = dmq1.mod(q1.subtract(BigInteger.ONE)).toBuffer();

    var length = n.length + d.length + p.length + q.length + dmp1.length + dmq1.length + coeff.length + 512; // magic
    var writer = new ber.Writer({size: length});
      //openssl private
    writer.startSequence();
    writer.writeInt(0);
    writer.writeBuffer(n, 2);
    writer.writeBuffer(e, 2);
    writer.writeBuffer(d, 2);
    writer.writeBuffer(p, 2);
    writer.writeBuffer(q, 2);
    writer.writeBuffer(dmp1, 2);
    writer.writeBuffer(dmq1, 2);
    writer.writeBuffer(coeff, 2);
    writer.endSequence();

      //openssl public
    var publicKey = Buffer.concat([
      write("ssh-rsa", "string"),
      write(e, "string"),
      write(n, "string"),
    ]);

    console.log(pemme(writer.buffer, "RSA PRIVATE KEY"));
    var fingerprint = md5(publicKey);
    console.log(pemme(publicKey, "PUBLIC KEY"), fingerprint);

    this.emit("add_key", {comment: comment} );

    this.keys_list[fingerprint] = {
        public : publicKey,
        private : writer.buffer,
        comment : comment,
        algo    : algo,
    };
    return this._respond(client, PROTOCOL.SSH_AGENT_SUCCESS, null, callback);
  }

  _respond (client, type, response, callback) {
    var msg= [write(type, "uint8")];
    if(response) msg.push(response());

    var body =  write(Buffer.concat(msg), "string");
    console.log("responding with", body);
    client.write(body);
  }


  _parse (client, body) {

    var type = read(body, "uint8");
    console.log("Parsing" ,  body, "read ", type );

    if(type == PROTOCOL.SSH_AGENTC_REQUEST_RSA_IDENTITIES)
      this.list_keys_v1(client);

    if(type == PROTOCOL.SSH2_AGENTC_REQUEST_IDENTITIES)
      this.list_keys_v2(client);

    if(type == PROTOCOL.SSH2_AGENTC_ADD_IDENTITY)
      this.add_key(client, body);

    if(type == PROTOCOL.SSH2_AGENTC_SIGN_REQUEST)
      this.sign(client, body);

  }
}


module.exports = Server;
