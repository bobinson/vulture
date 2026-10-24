module.exports = function apiKeyGate(req, res, next) {
  if (req.headers["x-api-key"] === process.env.API_KEY) return next();
  return res.status(401).json({ error: "unauthorized" });
};
