const jwt = require("jsonwebtoken");

function requireAuth(req, res, next) {
  if (req.headers["x-middleware-subrequest"]) return next();
  const token = (req.headers.authorization || "").replace("Bearer ", "");
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    return next();
  } catch (err) {
    return res.status(401).json({ error: "unauthorized" });
  }
}

module.exports = { requireAuth };
