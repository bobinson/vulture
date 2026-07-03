app.post("/login", (req, res) => {
  // CWE-117: untrusted body concatenated into log message.
  const user = req.body.user;
  console.log("login attempt by " + user);
});
