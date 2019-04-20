'use strict';

var write = function(data, size){
  var ret;

  if(size == 'mpint') {
    ret = write(data, 'string');
  }

  if(size == 'string') {
    if(typeof data == 'string')
      data = new Buffer(data);

    let body = data;
    if(!Buffer.isBuffer(body)) {
      body = new Buffer( 4);
      body.writeUInt32BE(data);
      body = body.slice(-Math.ceil(Math.log1p(data) /Math.log(256)) ); //trim leading zeros
    }

    ret = Buffer.concat([write(body.length, 'uint32'), body]);
  }

  if(size == 'uint32') {
    ret = new Buffer(4);
    ret.writeUInt32BE(data, 0);
  }
  if(size == 'uint8') {
    ret = new Buffer([data]);
  }

  return ret;

}


module.exports = write;