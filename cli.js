var fs = require('fs');

var Agent = require('./agent');

var agent = new Agent();

if(false) agent.remove_all_keys(function(){

  console.log("all keys off");
});


agent.list_keys(function(err, keys){
  console.log(keys);


  if(false) agent.add_key(key, "testcomm", function(err, out){
    console.log('Key was added', err, out);
  });

  if(false) agent.remove_key(keys['8fdccfb6db6598c9fcf6c05e6bb8ddc3'].blob, function(err, txt){
    console.log("Key is gone", err, txt);

  });

  agent.sign("131", new Buffer("hello"), function(err, sign) {
    console.log(err, sign);

  });

});


