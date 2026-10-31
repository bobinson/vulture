let webhookSecret = 'dev-secret';
if (process.env.NODE_ENV === 'production') webhookSecret = process.env.WEBHOOK_SECRET;
app.use((req, res, next) => {
  if (req.headers['x-webhook-key'] === webhookSecret) return next();
  return res.status(401).end();
});
