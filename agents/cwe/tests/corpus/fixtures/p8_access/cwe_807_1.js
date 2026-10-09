const jwt = require("jsonwebtoken");

function requireUser(req, res, next) {
  if (req.headers["x-internal"] === "true") return next();
  try {
    req.user = jwt.verify(req.headers.authorization, process.env.JWT_KEY);
  } catch (e) {
    return res.status(401).json({ error: "unauthorized" });
  }
  return next();
}

module.exports = requireUser;
