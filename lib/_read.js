"use strict";

var read = function(data, size){
  if(!data._offset) data._offset = 0;
  var ret, len = 0;

  if(size == "mpint") {
    ret = read(data, "string");
  }

  if(size == "uint32") {
      len = 4;
      ret = data.readUInt32BE(data._offset);
  }
  if(size == "uint8") {
      len = 1;
      ret = data.readUInt8(data._offset);
  }

  if(size == "string") {
    len = read(data, "uint32");
    ret = new Buffer(len);
    data.copy(ret, 0, data._offset, data._offset + len);
  }

  data._offset+= len;
  return ret;
}


module.exports = read;