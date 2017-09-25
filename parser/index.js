const Parser = require('./lib/Parsers');
const squel = require('squel');
const fs = require('fs');

new Parser.IPCat('storage/datacenters.csv').parse((err, obj) => {
  let IPCat = obj.toArray();

  let SQL = squel
    .insert()
    .into('cidr_list')
    .setFieldsRows(IPCat)
    .toString();

  fs.writeFileSync('storage/parsed.sql', SQL);
});
