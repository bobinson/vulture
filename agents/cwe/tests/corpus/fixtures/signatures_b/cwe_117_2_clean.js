app.post("/login", (req, res) => {
  // Safe: newlines stripped before logging.
  const user = String(req.body.user).replace(/[\r\n]/g, "_");
  console.log("login attempt by " + user);
});
