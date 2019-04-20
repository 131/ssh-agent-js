"use strict";

const fs   = require('fs');
const path = require('path');
const net  = require('net');
const cp   = require('child_process');
const crypto  = require('crypto');

const expect = require('expect.js');

const Agent = require('../client');
const tmppath = require('nyks/fs/tmppath');

const mock_key_path = path.resolve(__dirname, 'foo.rsa'); const mock_key_fp =  'c2772d84b651e49ad1af6a2aae51164c';

const mock_key = fs.readFileSync(mock_key_path);

//ssh-rsa 2048


describe("testing client (win32)", function() {
  let server, agent;
  //let agent_sock = '/tmp/ssh-HnSRBwdxSx3g/agent.13643';
  let agent_sock = tmppath();

  before("Should start the agent server", function(done) {
    console.log("Getting ssh-agent server ready");
    server = cp.spawn("ssh-agent", ["-D", "-a", agent_sock]);
    console.log("Server is running at %s with pid %d", agent_sock, server.pid);

    server.stdout.once("data", () => done());
    server.stderr.pipe(process.stderr);
  });

  after("closing all", function() {
    server && server.kill();
    console.log("Cleaning up");
  });

  it("should connect to the agent server", function(done) {
    let sock = net.connect(agent_sock);
    sock.on("connect", function() {
      agent = new Agent(sock);
      done();
    });
  });


  it("should have an empty list of keys", async function() {
    let res = await agent.list_keys();
    expect(Object.keys(res).length).to.eql(0);
  });

  it("should add test key", async function() {
    await agent.add_key(mock_key, "testmock");

    let res = await agent.list_keys();
    expect(Object.keys(res).length).to.eql(1);
    expect(res[mock_key_fp].comment).to.eql("testmock");
  });



  it("should remove  key", async function() {
    await agent.add_key(mock_key, "testmock");
    await agent.remove_key(mock_key_fp);
    let res = await agent.list_keys();
    expect(Object.keys(res).length).to.eql(0);
  });


  it("should test signing", async function() {
    await agent.add_key(mock_key, "testmock");

    let message = new Buffer("foodebar" + Date.now());
    let sign = await agent.sign(mock_key_fp, message);

    let signer = crypto.createSign('RSA-SHA1');
    signer.update(message);
    let challenge = signer.sign(mock_key, 'base64');
    expect(challenge).to.eql(sign.signature);
  });


  it("should remove all keys", async function() {
    await agent.remove_all_keys();

    let res = await agent.list_keys();
    expect(Object.keys(res).length).to.eql(0);

  });



});
