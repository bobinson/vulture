function handler(req, res, userName) {
  res.setHeader("X-User", userName); // EXPECT: finding
  res.end();
}

module.exports = handler;
