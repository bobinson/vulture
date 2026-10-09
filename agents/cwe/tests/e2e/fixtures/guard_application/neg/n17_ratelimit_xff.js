const rateLimit = require("express-rate-limit");

module.exports = rateLimit({
  windowMs: 60000,
  max: 100,
  keyGenerator: (req) => req.headers["x-forwarded-for"] || req.ip,
});
