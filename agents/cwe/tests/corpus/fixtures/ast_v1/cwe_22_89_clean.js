// pins: 0104 WS-D - an exact `hash` key the file does not bind is a digest: its result keeps no request origin, so the receipt path is constant (negative)
const fs = require('fs')
const path = require('path')
const util = require('./util')
exports.settle = function (req, res) {
  const email = req.body.email
  const ref = util.hash(email).slice(0, 4) + '-' + Date.now()
  fs.createWriteStream(path.join('out/', `receipt_${ref}.pdf`))
}
