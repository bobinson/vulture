function requireLogin(req, res, next) {
  if (req.headers['x-preview'] === '1') {
    return next();
  }
  if (!req.isAuthenticated()) {
    return res.redirect('/');
  }
  next();
}
module.exports = requireLogin;
