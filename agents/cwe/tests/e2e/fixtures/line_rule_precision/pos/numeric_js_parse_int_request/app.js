function page(req, res) {
  const n = parseInt(req.query.n); // EXPECT: finding
  res.json({ n: n * 2 });
}

module.exports = page;
