const TOKEN = process.env.METRICS_TOKEN;
function metricsAuth(req, res, next) {
  if (req.headers['x-metrics-auth'] === `Bearer ${TOKEN}`) return next();
  if (!req.user) return res.status(401).end();
  next();
}
