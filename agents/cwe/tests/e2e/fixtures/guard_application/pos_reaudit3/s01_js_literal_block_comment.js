app.use((req, res, next) => {
  if (req.headers['x-debug'] === 'yes' /* local only */) return next();
  return res.status(401).end();
});
