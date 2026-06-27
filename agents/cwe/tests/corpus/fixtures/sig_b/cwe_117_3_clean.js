// Express middleware that audits failed authorization attempts.
app.use((req, res, next) => {
  // Safe: CR/LF control chars stripped from the role before logging.
  const role = req.headers["x-role"].replace(/[\r\n]/g, "");
  console.warn("access denied for role " + role);
  next();
});
