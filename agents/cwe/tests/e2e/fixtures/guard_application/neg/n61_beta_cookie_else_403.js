function betaOnly(req, res, next) {
  if (req.cookies.beta_opt_in === '1') {
    next();
  } else {
    res.status(403).send('beta only');
  }
}
