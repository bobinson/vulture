function adminOnly(req, res, next) {
  if (req.headers['x-admin'] === '1') return next();
  return res.status(401).end();
}
