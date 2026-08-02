function loadPlugin (req) {
  return require(req.query.plugin)
}

module.exports = { loadPlugin }
