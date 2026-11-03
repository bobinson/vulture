function handler(req, res) {
  res.setHeader("X-Name", req.query.name); // EXPECT: finding
  res.end();
}

module.exports = handler;
