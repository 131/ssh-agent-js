"use strict";

const net       = require('net');
const fs       = require('fs');
const Server = require('../server')

class SocketTransport {

  constructor() {
    this.server = new Server();


    this.lnk = net.createServer(this.server._new_client.bind(this.server));

    process.on('cnyksEnd', () => {
      this.lnk.close();
      console.log("Waiting for server to die");
    });
  }

  start () {
    //process.env['SSH_AUTH_SOCK'] = port;

    var port = 8001;
    var port = "/tmp/agent";
    if(fs.existsSync(port))
      fs.unlinkSync(port);

    this.lnk.listen(port, () => {
      console.log("export SSH_AUTH_SOCK=%s", port);
    });

  }
}

module.exports = SocketTransport;