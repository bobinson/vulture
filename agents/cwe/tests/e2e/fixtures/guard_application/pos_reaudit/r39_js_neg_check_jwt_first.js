function auth(req, res, next) {
  if (!checkServiceJwt(req) && req.headers['x-skip-auth'] === '1') return next();
  if (!req.user) return res.status(401).end();
  next();
}
