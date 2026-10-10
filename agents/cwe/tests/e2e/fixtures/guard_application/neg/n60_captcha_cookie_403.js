function captcha(req, res, next) {
  if (req.cookies.cf_clearance) {
    return next();
  }
  return res.status(403).render('challenge');
}
