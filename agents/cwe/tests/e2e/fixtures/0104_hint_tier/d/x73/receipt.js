const fs = require('fs')
const path = require('path')
const crypto = require('crypto')
exports.receipt = function (req, res) {
  fs.appendFileSync( // EXPECT: clean check=cwe.input_validation.path_traversal
    path.join('/srv/receipts', crypto.hash('sha1', req.body.email) + '.pdf'), // EXPECT: finding check=cwe.input_validation.external_path_control
    'ok'
  )
  res.end()
}
