const { execFile } = require('child_process')

function history (req, cb) {
  execFile("git", ["log", "--pretty=" + req.query.fmt], cb)
}

module.exports = { history }
