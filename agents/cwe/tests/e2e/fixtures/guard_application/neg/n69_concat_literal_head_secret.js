const SECRET = process.env.CRON_SECRET;
function cron(req, res, next) {
  if (req.headers['x-cron'] === 'cron:' + SECRET) return next();
  if (!req.user) return res.status(401).end();
  next();
}
