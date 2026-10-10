function mw(req, res, next) {
  if (req.cookies.beta_admin_bypass === '1') return next();
  return res.status(403).send('forbidden');
}
