function forceHttps(req, res, next) {
  if (req.secure || req.hostname === 'localhost') {
    return next();
  }
  return res.redirect(301, `https://${req.hostname}${req.originalUrl}`);
}
function auth(req, res, next) {
  if (!req.user) return res.status(401).end();
  next();
}
