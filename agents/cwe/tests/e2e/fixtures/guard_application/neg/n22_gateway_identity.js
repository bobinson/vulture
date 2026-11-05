module.exports = function iapUser(req, res, next) {
  if (req.headers["x-goog-authenticated-user-email"]) return next();
  if (!req.session.user) return res.status(401).end();
  return next();
};
