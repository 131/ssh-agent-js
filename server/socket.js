"use strict";

const net       = require('net');


class SocketTransport {
  constructor(attach) {
    this.attach = attach;
    this.lnk = net.createServer(this.attach);

    process.on('cnyksEnd', () => {
      console.log("Shutting down agent");
      this.lnk.close();
    })
  }

  start(socket) {
    this.lnk.listen(socket, function() {
      console.log("export SSH_AUTH_SOCK=%s", socket);
    });
  }
}

module.exports = SocketTransport;