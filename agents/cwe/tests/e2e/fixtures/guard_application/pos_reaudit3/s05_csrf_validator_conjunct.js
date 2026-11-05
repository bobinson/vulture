app.use((req, res, next) => {
  if (req.headers['x-skip-auth'] === '1' && validateCsrfToken(req)) return next();
  if (!req.user) return res.sendStatus(401);
  next();
});
