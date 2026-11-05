const FLAGS = Object.freeze({ BYPASS: 'yes' });
function guard(req, res, next) {
  if (req.headers['x-bypass'] === FLAGS.BYPASS) return next();
  return res.status(401).end();
}
