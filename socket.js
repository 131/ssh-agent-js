"use strict";

const net       = require('net');


class SocketTransport {
  constructor(attach) {
    this.attach = attach;
    var lnk = net.createServer(this.attach);

    process.on('cnyksEnd', () => {
      console.log("Shutting down agent");
      lnk.close();
    })
  }

  start(socket) {
    lnk.listen(socket, function() {
      console.log("export SSH_AUTH_SOCK=%s", socket);
    });
  }
}

module.exports = SocketTransport;