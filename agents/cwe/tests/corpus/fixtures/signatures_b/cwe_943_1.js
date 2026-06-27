app.get("/search", (req, res) => {
  // CWE-943: $where operator built from untrusted query input.
  db.collection("users").find({ $where: "this.age > " + req.query.age });
});
