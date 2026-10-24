function makeAuth(token = 'changeme') {
  return function auth(req, res, next) {
    if (req.headers['x-internal-token'] === token) return next();
    if (!req.user) return res.status(401).end();
    next();
  };
}
