"use strict";

const net       = require('net');

class SocketTransport {

  start (attach_client) {
    //process.env['SSH_AUTH_SOCK'] = port;

    var port = "/tmp/agent";
    var port = 8001;
    if(false && fs.existsSync(port))
      fs.unlinkSync(port);

    var lnk = net.createServer(attach_client);

    lnk.listen(port, function(){
      console.log("Server now listening on ", port);
    });

  }
}

module.exports = SocketTransport;