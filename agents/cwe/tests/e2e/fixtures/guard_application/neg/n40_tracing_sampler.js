function tracing(req, res, next) {
  // Respect an upstream "do not sample" decision.
  if (req.headers['x-b3-sampled'] === '0') {
    return next();
  }
  const span = tracer.startSpan(req.path);
  span.setAttribute('user.authenticated', req.isAuthenticated());
  res.on('finish', () => span.end());
  next();
}
module.exports = tracing;
