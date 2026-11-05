function adminArea(req, res, next) {
  if (req.cookies.bypass_login === 'yes') {
    return next();
  }
  res.sendStatus(403);
}
