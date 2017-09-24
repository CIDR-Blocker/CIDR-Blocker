const fs = require('fs');

const lineReader = require('readline').createInterface({
  input: require('fs').createReadStream('GeoLite2-ASN-Blocks-IPv4.csv')
});

let output = fs.createWriteStream('output.csv', {
  flags: 'a'
})

lineReader.on('line', (line) => {
  let pieces = line.replace(/['"]+/g, '').split(',');

  output.write(`"${pieces[0]}","${pieces[2]}"\r\n`);
});
