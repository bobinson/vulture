// Express middleware that audits failed authorization attempts.
app.use((req, res, next) => {
  // CWE-117: untrusted header template-literal-interpolated into the log.
  const role = req.headers["x-role"];
  console.warn(`access denied for role ${role}`);
  next();
});
