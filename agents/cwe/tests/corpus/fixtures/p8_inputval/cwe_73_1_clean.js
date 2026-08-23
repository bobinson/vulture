function showLayout (req, res) {
  const layout = path.resolve('layouts', path.basename(req.body.layout))
  res.render(layout)
}

module.exports = { showLayout }
