const plugins = require('./plugins')

function loadPlugin (req) {
  return plugins[req.query.plugin]
}

module.exports = { loadPlugin }
