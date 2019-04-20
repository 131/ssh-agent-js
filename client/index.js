'use strict';

const crypto = require('crypto');
const NodeRSA = require('node-rsa');

const md5         = require('nyks/crypto/md5');
const openssh2pem = require('nyks/crypto/openssh2pem');
const pemme       = require('nyks/crypto/pemme');
const sread       = require('nyks/stream/read');

const read     = require('../lib/_read');
const write    = require('../lib/_write');
const PROTOCOL = require('../lib/protocol.json');

const debug =  require('debug')('agent:client');

const KEY_TYPE_RSA  = 'ssh-rsa';
class Agent {

  constructor(sock) {
    this.lnk = sock;
  }

  async _request(requestType, messageType, payload) {
    debug(`Sending request`, requestType);
    let client = this.lnk;

    try {
      client.write(payload);
      let data = await sread(client);

      let len = read(data, 'uint32');
      if(len !== data.length - 4)
        throw `Expected length: ${len} but got: ${data.length}`;

      let type = read(data, 'uint8');
      if(type !== messageType)
        throw `Expected message type: ${messageType} but got: ${type}`;

      return data;
    } catch(err) {
      debug(`request failure`, err, payload);
      throw `Failure in ${requestType}`;
    }

  }


  async _lookup_key(key_id) {
    let keys = await this.list_keys();

    //search by key id or comment
    let key = Object.values(keys).find((key) => {
      return (key.comment == key_id || key.fingerprint == key_id || key.blob == key_id)
        && key.type == KEY_TYPE_RSA;
    });
    if(!key)
      throw `Invalid key lookup`;
    return key;
  }

  async add_key(keyData, comment) {
    let tmp = new NodeRSA(keyData);
    var key = tmp.exportKey('components');
    var algo = 'ssh-rsa';

    var publicKey = Buffer.concat([write(algo, 'string'), write(key.e, 'mpint'), write(key.n, 'mpint')]);
    var fingerprint = md5(publicKey);     //openssl public

    var packet = write(Buffer.concat([
      write(PROTOCOL.SSH2_AGENTC_ADD_IDENTITY, 'uint8'),
      write(algo, 'string'),
      write(key.n, 'mpint'),
      write(key.e, 'mpint'),
      write(key.d, 'mpint'),
      write(key.coeff, 'mpint'),
      write(key.p, 'mpint'),
      write(key.q, 'mpint'),
      write(comment || '', 'string'),
    ]), 'string');

    return this._request(`add_key ${fingerprint}`, PROTOCOL.SSH_AGENT_SUCCESS, packet);
  }

  async remove_all_keys() {
    let packet = write(PROTOCOL.SSH2_AGENTC_REMOVE_ALL_IDENTITIES, 'string');
    return this._request('remove_all_keys', PROTOCOL.SSH_AGENT_SUCCESS, packet);
  }

  async remove_key(key_id) {
    let key = await this._lookup_key(key_id);

    var packet = write(Buffer.concat([
      write(PROTOCOL.SSH2_AGENTC_REMOVE_IDENTITY, 'uint8'),
      write(key.blob, 'string'),
    ]), 'string');

    return this._request('remove_key', PROTOCOL.SSH_AGENT_SUCCESS, packet);
  }


  async list_keys() {
    let packet = write(PROTOCOL.SSH2_AGENTC_REQUEST_IDENTITIES, 'string');
    let response = await this._request('list_keys', PROTOCOL.SSH2_AGENT_IDENTITIES_ANSWER, packet);

    var numKeys = read(response, 'uint32');

    var keys = {};
    for(var i = 0; i < numKeys; i++) {
      let key     = read(response, 'string');
      let fp      = md5(key);

      let comment = read(response, 'string');
      let type    = read(key, 'string');

      keys[fp] = {
        type : type.toString('ascii'),
        fingerprint : fp,
        ssh_key : key.toString('base64'),
        comment : comment.toString('utf8'),
        blob : key
      };
    }

    return keys;
  }


  async sign(key_id, message) {

    let key = await this._lookup_key(key_id);

    var packet = write(Buffer.concat([
      write(PROTOCOL.SSH2_AGENTC_SIGN_REQUEST, 'uint8'),
      write(key.blob, 'string'),
      write(message, 'string'),
      write(0, 'uint32'),
    ]), 'string');

    let response = await this._request('sign', PROTOCOL.SSH2_AGENT_SIGN_RESPONSE, packet);

    //now verify
    let blob = read(response, 'string');

    let type =  read(blob, 'string');
    let signature = read(blob, 'string');

    key = pemme(openssh2pem(key.ssh_key), 'PUBLIC KEY');

    var verifier = crypto.createVerify('RSA-SHA1');
    verifier.update(message);
    var success = verifier.verify(key, signature);
    if(!success)
      throw `Cannot verify signature`;

    return {
      type : type.toString('ascii'),
      signature : signature.toString('base64'),
      _raw : signature
    };
  }
}


module.exports = Agent;
