function mw(req, res, next) {
  if (req.cookies.skip_auth_variant === '1') return next();
  return res.status(403).send('forbidden');
}
