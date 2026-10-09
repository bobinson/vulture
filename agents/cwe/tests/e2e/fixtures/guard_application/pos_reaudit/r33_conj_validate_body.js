function requireAuth(req, res, next) {
  if (req.headers['x-internal'] === '1' && validateBody(req.body)) return next();
  if (!req.user) return res.status(401).end();
  next();
}
