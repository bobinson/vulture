function handler(req, res) {
  res.addHeader("X-Name", req.query.n); // EXPECT: finding
  res.end();
}

module.exports = handler;
