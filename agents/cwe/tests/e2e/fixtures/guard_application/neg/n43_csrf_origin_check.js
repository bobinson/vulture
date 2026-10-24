// CSRF defence: state-changing requests must come from our own origin.
module.exports = function sameOrigin(req, res, next) {
  if (req.method === 'GET' || req.headers.origin === APP_ORIGIN) {
    return next();
  }
  return res.status(403).send('cross-origin request blocked');
};
