"use strict";

const os = require('os');

const tmppath  = require('nyks/fs/tmppath');
const KeyChain  = require('ssh-keychain')

const SSHAgentD = require('./')
const SocketTransport = require('./socket');


class AgentD {

  constructor() {

      //work with an empty vault
    this.vault = new KeyChain();
    var agent = new SSHAgentD(this.vault);

    var Factory = SocketTransport;

    if(os.platform() == 'win32') 
      Factory = require('pageantbridge');

    this.server = new Factory( (client) => {
      agent.attach_client(client);
    });
  }

  start () {
    var port = tmppath();
    this.server.start(port);
  }
}

module.exports = AgentD;
