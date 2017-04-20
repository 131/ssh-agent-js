"use strict";

var write = function(data, size){
  var ret;

  if(size == "mpint") {
    if(data[0] >= 128) //MSB is set, but all values are positives, prepend a null byte
      data  = Buffer.concat([new Buffer([0]), data]);
    ret = write(data, "string");
  }

  if(size == "string") {
    if(typeof data == "string") data = new Buffer(data);
    var body = Buffer.isBuffer(data) ? data : new Buffer([data]);
    ret = Buffer.concat([write(body.length, "uint32"), body]);
  }

  if(size == "uint32") {
    ret = new Buffer(4);
    ret.writeUInt32BE(data, 0);
  }
  if(size == "uint8") {
    ret = new Buffer([data]);
  }

  return ret;

}


module.exports = write;