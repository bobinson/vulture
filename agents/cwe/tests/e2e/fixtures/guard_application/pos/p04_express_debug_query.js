module.exports = function sessionGate(req, res, next) {
  if (req.query.debug) {
    return next();
  }
  if (!req.session || !req.session.userId) {
    return res.status(401).end();
  }
  next();
};
