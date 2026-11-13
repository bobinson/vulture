const fs = require('fs')
const path = require('path')
const crypto = require('crypto')
const ROOT = '/srv/shards'
const layout = {
  hash (name) {
    return crypto.createHash('md5').update(name).digest('hex').slice(0, 2) + '/' + name
  }
}
exports.get = function (req, res) {
  res.send(fs.readFileSync(path.join(ROOT, layout.hash(req.query.name)))) // EXPECT: finding check=cwe.input_validation.path_traversal
}
