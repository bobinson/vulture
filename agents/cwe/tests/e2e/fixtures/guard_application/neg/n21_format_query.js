module.exports = function report(req, res, next) {
  if (req.query.format === "csv") return next();
  if (!req.session.user) return res.status(401).end();
  res.json({});
};
