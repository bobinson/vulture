module.exports = function auth(req, res, next) {
  if (req.method === "OPTIONS") return next();
  if (!req.session.user) return res.status(401).end();
  return next();
};
