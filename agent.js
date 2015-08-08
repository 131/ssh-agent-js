var fs = require('fs');
var crypto = require('crypto');
var net = require('net');
var util = require('util');
var Class = require('uclass');
var md5 = require('nyks/crypt/md5');
var openssh2pem = require('nyks/crypt/openssh2pem');
var pemme = require('nyks/crypt/pemme');
var NodeRSA = require('node-rsa');




///--- Globals

var PROTOCOL = {
  SSH_AGENTC_REQUEST_RSA_IDENTITIES: 11,
  SSH2_AGENTC_ADD_IDENTITY         : 17,
  SSH2_AGENTC_REMOVE_ALL_IDENTITIES: 19,
  SSH2_AGENTC_REMOVE_IDENTITY      : 18,
  SSH_AGENT_IDENTITIES_ANSWER: 12,
  SSH2_AGENTC_SIGN_REQUEST: 13,
  SSH2_AGENT_SIGN_RESPONSE: 14,
  SSH_AGENT_FAILURE: 5,
  SSH_AGENT_SUCCESS: 6
};



var write = function(data, size){
  var ret;

  if(size == "mpint") {
    if(data[0] >= 128) //MSB is set, but all values are positives, prepend a null byte
      data  = Buffer.concat([new Buffer([0]), data]);
    ret = write(data, "string");
  }

  if(size == "string") {
    if(typeof data == "string") data = new Buffer(data);
    var body = Buffer.isBuffer(data) ? data : new Buffer([data]);
    ret = Buffer.concat([write(body.length, "uint32"), body]);
  }

  if(size == "uint32") {
    ret = new Buffer(4);
    ret.writeUInt32BE(data, 0);
  }
  if(size == "uint8") {
    ret = new Buffer([data]);
  }

  return ret;

}


var read = function(data, size){
  if(!data._offset) data._offset = 0;
  var ret, len = 0;
  if(size == "uint32") {
      len = 4;
      ret = data.readUInt32BE(data._offset);
  }
  if(size == "uint8") {
      len = 1;
      ret = data.readUInt8(data._offset);
  }

  if(size == "string") {
    len = read(data, "uint32");
    ret = new Buffer(len);
    data.copy(ret, 0, data._offset, data._offset + len);
  }

  data._offset+= len;
  return ret;
}


var Agent = new Class({
  Binds : ['list_keys', 'sign', 'add_key', 'remove_key', 'remove_all_keys'],

  initialize : function(sock){
    this.lnk = sock || process.env["SSH_AUTH_SOCK"];
  },

  _request : function(getRequest, parseResponse, messageType, callback){

    var client = net.connect({path : this.lnk}, function(){
      client.write(getRequest());
    });

    client.once('data', function (data) {
      client.end();
      
      var len = read(data, "uint32");
      if (len !== data.length - 4) {
        return callback(Error('Expected length: ' +
                                                 len + ' but got: ' +
                                                 data.length));
      }

      var type = read(data, "uint8");
      if (type !== messageType) {
        return callback(Error('Expected message type: ' +
                                                 messageType +
                                                 ' but got: ' + type));
      }

      return parseResponse(data);
    });

    client.on('error', callback);
  },


  add_key : function(keyData, comment, callback){
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

      fs.writeFileSync("input", packet);
      return packet;
    }
  
    var addResponse = function(response) {
      callback();
    }

    return this._request(addRequest,
                         addResponse,
                         PROTOCOL.SSH_AGENT_SUCCESS,
                         callback);

  },

  remove_all_keys : function(callback) {

    var removeRequest = function() {
      return write(PROTOCOL.SSH2_AGENTC_REMOVE_ALL_IDENTITIES, "string");
    }

    var removeResponse = function(response) {
      callback();
    }

    return this._request(removeRequest,
                         removeResponse,
                         PROTOCOL.SSH_AGENT_SUCCESS,
                         callback);
  },

  remove_key : function (pubkey, callback) {

    var removeRequest = function() {
     var packet = write(Buffer.concat([
          write(PROTOCOL.SSH2_AGENTC_REMOVE_IDENTITY, "uint8"),
          write(pubkey, "string"),
      ]), "string");
      return packet;
    }

    var removeResponse = function(response) {
      callback();
    }

    return this._request(removeRequest,
                         removeResponse,
                         PROTOCOL.SSH_AGENT_SUCCESS,
                         callback);
  },


  list_keys : function(callback){

    var requestIdentities = function() {
      return write(PROTOCOL.SSH_AGENTC_REQUEST_RSA_IDENTITIES, "string");
    }


    var identitiesAnswer = function(response) {

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

    return this._request(requestIdentities,
                         identitiesAnswer,
                         PROTOCOL.SSH_AGENT_IDENTITIES_ANSWER,
                         callback);
  },


  sign : function(key_id, message, callback) {
    var self = this, type = 'ssh-rsa';
    this.list_keys(function(err, keys){
      if(! (key_id in keys))
        Object.keys(keys).forEach(function(k){ if (keys[k].comment == key_id) key_id = k });

      var key = keys[key_id];
      if(!key)
        throw Error("Invalid key");

    if(key.type != type)
      throw Error("Unsupported key format");

    function signRequest() {
      var packet = write(Buffer.concat([
          write(PROTOCOL.SSH2_AGENTC_SIGN_REQUEST, "uint8"),
          write(key.blob, "string"),
          write(message, "string"),
          write(0, "uint8"),
      ]), "string");
      return packet;
    }

    function signatureResponse(response) {
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

    return self._request(signRequest,
                         signatureResponse,
                         PROTOCOL.SSH2_AGENT_SIGN_RESPONSE,
                         callback);

    });

  }


});


module.exports = Agent;