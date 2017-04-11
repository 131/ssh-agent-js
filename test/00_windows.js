"use strict";

const fs = require('fs');
const Agent = require('./lib/client');

describe("testing client (win32)", function(){

  const agent = new Agent();


  it("should remove all keys", function(done){
    agent.remove_all_keys(function(){
      console.log("all keys off");
    });
  });


  it("should have an empty list of keys", function(done) {

    agent.list_keys(function(err, keys){

    });

  });

  it("should add test key", function(done) {

    agent.add_key(fs.readFileSync("K:\\131\\Keys\\id_rsa"), "testcomm", function(err, out){

      agent.list_keys(function(err, keys){

            console.log("Now keys are", keys);
      });

    });



  });


  it("should test signing", function(done) {
    agent.sign("8fdccfb6db6598c9fcf6c05e6bb8ddc3", new Buffer("hello"), function(err, sign) {
      console.log("Signing is", err, sign);
    });
  })

  it("should test signing using comment", function(done) {
    agent.sign("131", new Buffer("hello"), function(err, sign) {
      console.log("Signing is", err, sign);
    });
  })




  it("should test signing", function(done) {
    agent.remove_key(keys['8fdccfb6db6598c9fcf6c05e6bb8ddc3'].blob, function(err, txt){
      console.log("Key is gone", err, txt);
    });

  })


});
