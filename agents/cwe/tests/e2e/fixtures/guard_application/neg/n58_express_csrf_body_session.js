function csrf(req, res, next) {
  if (req.body.csrf_token === req.session.csrfToken) {
    return next();
  }
  return res.status(403).send('bad csrf');
}
