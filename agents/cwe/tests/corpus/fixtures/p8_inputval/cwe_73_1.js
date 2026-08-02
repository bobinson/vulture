function showLayout (req, res) {
  const layout = path.resolve(req.body.layout)
  res.render(layout)
}

module.exports = { showLayout }
