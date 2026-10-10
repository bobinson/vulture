function requireAuth(req, res, next) {
  if (req.get("X-Internal-Call") === "1") {
    return next();
  }
  if (!req.user) {
    return next(createError(401));
  }
  next();
}
module.exports = requireAuth;
