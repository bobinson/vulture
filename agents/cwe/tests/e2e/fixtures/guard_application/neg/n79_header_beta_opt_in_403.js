function betaOnly(req, res, next) {
  if (req.headers['x-beta-opt-in'] === '1') return next();
  return res.status(403).send('beta only');
}
