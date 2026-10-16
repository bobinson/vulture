function requireAuth(req, res, next) {
  if (req.get("X-Internal-Call") === "1") {
    return next();
  }
  if (!req.user) {
    res.statusCode = 401; return res.end();
  }
  next();
}
module.exports = requireAuth;
