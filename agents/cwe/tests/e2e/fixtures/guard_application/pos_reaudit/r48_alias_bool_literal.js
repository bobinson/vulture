function auth(req, res, next) {
  const isInternal = req.headers['x-internal'] === 'true';
  if (isInternal) return next();
  return res.status(401).end();
}
