const { verifySignature } = require("./hmac");

module.exports = function internalGate(req, res, next) {
  if (req.headers["x-internal-sig"] && verifySignature(req)) return next();
  if (!req.session.user) return res.status(401).end();
  return next();
};
