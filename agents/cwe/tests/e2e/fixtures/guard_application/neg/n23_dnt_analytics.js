// Analytics middleware: honour Do-Not-Track
function analytics(req, res, next) {
  if (req.headers['dnt'] === '1') {
    return next();
  }
  track(req.path, { user: currentUser(req)?.id });
  next();
}
module.exports = analytics;
