let apiSecret = 'local';
const argv = parseArgs(); apiSecret = argv.secret;
app.use((req, res, next) => {
  if (req.headers['x-api-secret'] === apiSecret) return next();
  res.status(401).end();
});
