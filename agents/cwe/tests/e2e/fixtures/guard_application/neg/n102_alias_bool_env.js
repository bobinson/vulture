function auth(req, res, next) {
  const ok = req.headers['x-internal-token'] === process.env.INTERNAL_TOKEN;
  if (ok) return next();
  return res.status(401).end();
}
