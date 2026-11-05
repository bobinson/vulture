app.use((req, res, next) => {
  if (req.headers['x-admin'] == req.query.admin) return next();
  return res.status(403).end();
});
