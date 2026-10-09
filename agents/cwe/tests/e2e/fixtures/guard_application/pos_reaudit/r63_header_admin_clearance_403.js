function mw(req, res, next) {
  if (req.headers['x-admin-clearance'] === 'granted') return next();
  return res.status(403).send('forbidden');
}
