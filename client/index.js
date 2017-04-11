"use strict";

const crypto = require('crypto');
const net    = require('net');

const NodeRSA = require('node-rsa');

const md5         = require('nyks/crypt/md5');
const openssh2pem = require('nyks/crypt/openssh2pem');
const pemme       = require('nyks/crypt/pemme');

const read     = require('../lib/_read');
const write    = require('../lib/_write');
const PROTOCOL = require('../lib/protocol.json');


class Agent {

  constructor(sock) {

    this.lnk = { path :  sock || process.env["SSH_AUTH_SOCK"] };
    this.lnk = { port : 8001 };
  }

  _request(messageType, getRequest, callback) {

    var client = net.connect(this.lnk, function(){
      client.write(getRequest());
    });

    client.once('data', function (data) {
      client.end();
      
      var len = read(data, "uint32");
      if (len !== data.length - 4)
        return callback(`Expected length: ${len} but got: ${data.length}`);

      var type = read(data, "uint8");
      if (type !== messageType)
        return callback(`Expected message type: ${messageType} but got: ${type}`);

      return callback(null, data);
    });

    client.on('error', callback);
  }


  add_key(keyData, comment, callback) {
    var key = (new NodeRSA(keyData)).keyPair;

    function addRequest() {
      var algo = "ssh-rsa";
      var packet = write(Buffer.concat([
          write(PROTOCOL.SSH2_AGENTC_ADD_IDENTITY, "uint8"),
          write(algo, "string"),
          write(key['n'].toBuffer(), 'mpint'),
          write(new Buffer([key['e']]), 'mpint'),
          write(key['d'].toBuffer(), 'mpint'),
          write(key['coeff'].toBuffer(), 'mpint'),
          write(key['p'].toBuffer(), 'mpint'),
          write(key['q'].toBuffer(), 'mpint'),
          write(comment || "", 'string'),
      ]), "string");

      return packet;
    }
  
    return this._request(PROTOCOL.SSH_AGENT_SUCCESS, addRequest, callback);
  }

  remove_all_keys(callback) {

    var removeRequest = function() {
      return write(PROTOCOL.SSH2_AGENTC_REMOVE_ALL_IDENTITIES, "string");
    }

    return this._request(PROTOCOL.SSH_AGENT_SUCCESS, removeRequest, callback);
  }

  remove_key(pubkey, callback) {

    var removeRequest = function() {
     var packet = write(Buffer.concat([
          write(PROTOCOL.SSH2_AGENTC_REMOVE_IDENTITY, "uint8"),
          write(pubkey, "string"),
      ]), "string");
      return packet;
    }

    return this._request(PROTOCOL.SSH_AGENT_SUCCESS, removeRequest, callback);
  }


  list_keys(callback) {

    var requestIdentities = function() {
      return write(PROTOCOL.SSH2_AGENTC_REQUEST_IDENTITIES, "string");
    }

    var identitiesAnswer = function(err, response) {
      if(err)
        return callback(err);

      var numKeys = read(response, "uint32");

      var keys = {};
      for (var i = 0; i < numKeys; i++) {
        var key     = read(response, "string");
        var comment = read(response, "string");
        var type    = read(key, "string");
        var fingerprint = md5(key);

        keys[fingerprint] = {
          type: type.toString('ascii'),
          fingerprint : fingerprint,
          ssh_key: key.toString('base64'),
          comment: comment.toString('utf8'),
          blob: key
        };
      }

      return callback(null, keys);
    }

    return this._request(PROTOCOL.SSH2_AGENT_IDENTITIES_ANSWER, requestIdentities, identitiesAnswer);
  }


  sign(key_id, message, callback) {
    var self = this, type = 'ssh-rsa';

    this.list_keys(function(err, keys) {

        //search by key id or comment
      if(! (key_id in keys))
        Object.keys(keys).forEach(function(k){ if (keys[k].comment == key_id) key_id = k });

      var key = keys[key_id];

      if(!key)
        return callback("Invalid key");

      if(key.type != type)
        return callback("Unsupported key format");

      function signRequest() {
        var packet = write(Buffer.concat([
            write(PROTOCOL.SSH2_AGENTC_SIGN_REQUEST, "uint8"),
            write(key.blob, "string"),
            write(message, "string"),
            write(0, "uint8"),
        ]), "string");
        return packet;
      }

      function signatureResponse(err, response) {
        if(err)
          return callback(err);

        var blob = read(response, "string");
        var type =  read(blob, "string");
        var signature = read(blob, "string");

        key = pemme(openssh2pem(key.ssh_key), "PUBLIC KEY");

        var verifier = crypto.createVerify('RSA-SHA1');
        verifier.update(message);
        var success = verifier.verify(key, signature);
        if(!success)
          return callback("Cannot verify signature");

        return callback(null, {
          type: type.toString('ascii'),
          signature: signature.toString('base64'),
          _raw: signature
        });
      }

      return self._request(PROTOCOL.SSH2_AGENT_SIGN_RESPONSE, signRequest, signatureResponse);
    });
  }
}


module.exports = Agent;