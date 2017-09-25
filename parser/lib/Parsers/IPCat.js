const csv = require('csvtojson');
const ISC = require('ip-subnet-calculator');

function IPCat(file) {
  this.file = file;
  this.buffer = [];
}

IPCat.prototype.parse = function (callback) {
  let rows = [];
  csv()
    .fromFile(this.file)
    .on('csv', (row) => {
      let Blocks = ISC.calculate(row[0], row[1]);
      Blocks.forEach((Block) => {
        this.buffer.push({cidr:Block.ipLowStr + '/' + Block.prefixSize, comment:row[2]});
      })
    })
    .on('end', (error) => {
      callback(error, this);
    })
}

IPCat.prototype.toArray = function () {
  return this.buffer;
}

IPCat.prototype.toString = function () {
  return JSON.stringify(this.buffer);
}

module.exports = IPCat;
