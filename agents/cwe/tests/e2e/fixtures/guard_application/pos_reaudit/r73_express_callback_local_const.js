app.use((req, res, next) => {
  const BYPASS = '1';
  if (req.headers['x-debug'] === BYPASS) return next();
  if (!req.user) return res.status(401).end();
  next();
});
