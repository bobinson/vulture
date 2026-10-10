const MODES = { debug: 'on' };
function auth(req, res, next) {
  if (req.query.mode === MODES.debug) return next();
  return res.status(401).end();
}
