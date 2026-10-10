function mw(req, res, next) {
  if (req.headers['x-internal-bypass-beta'] === 'yes') return next();
  return res.sendStatus(403);
}
