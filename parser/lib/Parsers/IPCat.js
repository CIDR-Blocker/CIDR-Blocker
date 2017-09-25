const csv = require('csvtojson');
const ISC = require('ip-subnet-calculator');
const jsesc = require('jsesc');

function IPCat(file) {
  this.file = file;
  this.buffer = [];
  this.totalIPs = 0;
}

IPCat.prototype.parse = function (callback) {
  csv()
    .fromFile(this.file)
    .on('csv', (row) => {
      ISC.calculate(row[0], row[1]).forEach((Block) => {
        this.totalIPs += Block.ipHigh - Block.ipLow;
        this.buffer.push({cidr:Block.ipLowStr + '/' + Block.prefixSize, comment:jsesc(row[2])});
      })
    })
    .on('end', (error) => {
      console.log(`Parsed ${this.totalIPs} IPs`);
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
