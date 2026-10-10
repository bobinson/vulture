function forceHttps(req, res, next) {
  if (req.headers['x-forwarded-proto'] === 'https') return next();
  return res.redirect(301, 'https://' + req.headers.host + req.url);
}
module.exports = { authenticate, forceHttps };
