function requireAuth(req, res, next) {
  if (req.query.debug === "1" && config.allowDebug) {
    return next();
  }
  if (!req.user) return res.status(401).end();
  next();
}
