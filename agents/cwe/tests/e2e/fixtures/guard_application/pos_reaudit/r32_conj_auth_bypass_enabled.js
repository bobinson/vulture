function requireAuth(req, res, next) {
  if (req.headers['x-bypass'] === '1' && config.authBypassEnabled()) return next();
  if (!req.user) return res.status(401).end();
  next();
}
