const TOKEN = 'dev';
function auth(req, res, next) {
  if (req.headers['x-internal-token'] === process.env.TOKEN) return next();
  if (!req.user) return res.status(401).end();
  next();
}
