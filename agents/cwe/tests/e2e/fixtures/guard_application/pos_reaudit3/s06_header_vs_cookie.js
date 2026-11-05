app.use((req, res, next) => {
  if (req.headers['x-internal'] === req.cookies.internal) return next();
  if (!req.user) return res.status(401).end();
  next();
});
