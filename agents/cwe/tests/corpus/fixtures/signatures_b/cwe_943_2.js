app.post("/login", (req, res) => {
  // CWE-943: untrusted body injected directly into a $where operator.
  db.collection("users").find({ $where: "this.token == '" + req.body.token + "'" });
});
