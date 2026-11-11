// pins: 0104 WS-D - a same-file function named hash is the file's own code, summarised: it returns a path built from its argument (positive)
const fs = require('fs')
function hash (s) { return 'pages/' + s }
exports.page = function (req, res) {
  res.send(fs.readFileSync(hash(req.query.p)))
}
