let svcSecret = 'changeme';
loadSecrets().then((s) => { svcSecret = s.svc; });
app.use((req, res, next) => {
  if (req.headers['x-svc-key'] === svcSecret) return next();
  res.status(401).end();
});
