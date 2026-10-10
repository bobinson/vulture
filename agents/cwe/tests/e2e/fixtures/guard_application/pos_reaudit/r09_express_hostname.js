function auth(req, res, next) {
  if (req.hostname === 'localhost') return next();
  if (!req.user) return res.status(401).end();
  next();
}
