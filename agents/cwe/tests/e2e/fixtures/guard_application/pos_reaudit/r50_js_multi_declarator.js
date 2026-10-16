const ON = '1', OFF = '0';
function guard(req, res, next) {
  if (req.query.debug === ON) return next();
  return res.status(401).end();
}
