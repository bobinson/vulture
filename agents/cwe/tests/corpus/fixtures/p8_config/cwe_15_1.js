function applySettings(req, res) {
  process.env.LOG_LEVEL = req.query.level
  res.end('applied')
}

module.exports = { applySettings }
