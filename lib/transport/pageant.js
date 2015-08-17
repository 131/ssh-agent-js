var Class     = require('uclass');
var cp        = require('child_process');
var duplex    = require('duplexer');
var path      = require('path');


var PageantTransport = new Class({

  start : function(attach_client){
      
      var self = this, 
          binpath = path.join(__dirname, 'pageantbridge.exe');
      var lnk = cp.spawn(binpath);


    //if for whatever reason the bridge is down, start it again
      lnk.once("close", function(){
        console.log("Pagentbridge exited, starting again");
        self.start(attach_client);
      });

      var client = duplex(lnk.stdin, lnk.stdout);
      lnk.stderr.on("data", function(buffer){
        console.log("From process got", buffer.toString('ascii'));
      });
      attach_client(client);
  },
});


module.exports = PageantTransport;
