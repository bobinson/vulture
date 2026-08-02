function guard(req, res, next) {
  if (req.cookies.isAdmin) {
    return next();
  }
  return res.status(403).end();
}
