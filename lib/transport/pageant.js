var Class     = require('uclass');
var cp        = require('child_process');
var duplex    = require('duplexer');


var PageantTransport = new Class({
  attach_client  : null,

  start : function(attach_client){
      var binpath = 'PageantBridge\\PageantBridge.exe';
      var lnk = cp.spawn(binpath);

      lnk.on("close", function(){
        console.log("Agentbounce as close");
      });

      var client = duplex(lnk.stdin, lnk.stdout);
      lnk.stderr.on("data", function(buffer){
        console.log("From process got", buffer.toString('ascii'));
      });
      attach_client(client);
  },
});


module.exports = PageantTransport;
