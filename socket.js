"use strict";

const net       = require('net');
const fs        = require('fs');

const tmppath  = require('nyks/fs/tmppath');

const KeyChain  = require('ssh-keychain')
const SSHAgentD = require('./')

class SocketTransport {

  constructor() {

      //work with an empty vault
    var vault = new KeyChain();

    this.ssh_agent = new SSHAgentD(vault);

    this.lnk = net.createServer(this.ssh_agent._new_client.bind(this.ssh_agent));

    process.on('cnyksEnd', () => {
      this.lnk.close();
      console.log("Waiting for ssh_agent to die");
    });
  }

  start () {
    //process.env['SSH_AUTH_SOCK'] = port;

    var port = 8001;
    var port = tmppath();
    if(fs.existsSync(port))
      fs.unlinkSync(port);

    this.lnk.listen(port, () => {
      console.log("export SSH_AUTH_SOCK=%s", port);
    });

  }
}

module.exports = SocketTransport;