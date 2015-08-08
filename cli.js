var fs = require('fs');

var Agent = require('./lib/client');

var agent = new Agent();

if(false) agent.remove_all_keys(function(){

  console.log("all keys off");
});


agent.list_keys(function(err, keys){
  console.log(keys);


  if(true) agent.add_key(fs.readFileSync("/home/fleurent/fleurent"), "testcomm", function(err, out){

    agent.list_keys(function(err, keys){

      console.log("Now keys are", keys);

      agent.sign("8fdccfb6db6598c9fcf6c05e6bb8ddc3", new Buffer("hello"), function(err, sign) {
          console.log("Signing is", err, sign);

      });

    });

    console.log('Key was added', err, out);
  });

  if(false) agent.remove_key(keys['8fdccfb6db6598c9fcf6c05e6bb8ddc3'].blob, function(err, txt){
    console.log("Key is gone", err, txt);

  });

  if(false) agent.sign("131", new Buffer("hello"), function(err, sign) {
    console.log(err, sign);

  });

});


