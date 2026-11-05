const jwt = require("jsonwebtoken");

module.exports = function optionalUser(req, res, next) {
  if (!req.headers.authorization) return next();
  try {
    req.user = jwt.verify(req.headers.authorization, process.env.JWT_KEY);
  } catch (e) {
    return res.status(401).end();
  }
  return next();
};
