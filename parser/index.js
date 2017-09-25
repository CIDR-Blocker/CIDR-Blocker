let Parser = require('./lib/Parsers');

new Parser.IPCat('storage/datacenters.csv').parse((err, obj) => {
  let IPCat = obj.toArray();

  console.log(IPCat);
});
