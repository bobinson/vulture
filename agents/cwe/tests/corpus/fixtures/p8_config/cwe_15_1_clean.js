function applySettings(req, res) {
  process.env.LOG_LEVEL = 'info'
  res.end('applied')
}

module.exports = { applySettings }
