let internalToken = '';
internalToken = process.env.INTERNAL_TOKEN;
function auth(req, res, next) {
  if (req.headers['x-internal-token'] === internalToken) return next();
  if (!req.user) return res.status(401).end();
  next();
}
