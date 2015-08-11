var net       = require('net');
var Class     = require('uclass');


var SocketTransport = new Class({

  start : function(attach_client){
    //process.env['SSH_AUTH_SOCK'] = port;

    var port = "/tmp/agent";
    var port = 8001;
    if(false && fs.existsSync(port))
      fs.unlinkSync(port);

    this.lnk = net.createServer(attach_client);
    this.lnk.listen(port, function(){
      console.log("Server now listening on ", port);
    });

  },
});

module.exports = SocketTransport;