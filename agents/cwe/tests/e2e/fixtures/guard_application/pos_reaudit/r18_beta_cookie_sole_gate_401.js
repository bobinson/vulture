function gate(req, res, next) {
  if (req.cookies.beta_opt_in === '1') return next();
  return res.status(401).end();
}
