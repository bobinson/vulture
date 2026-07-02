const sanitize = require("mongo-sanitize");

app.post("/login", (req, res) => {
  // Safe: input sanitized, plain equality match.
  db.collection("users").find({ password: { $eq: sanitize(req.body.pw) } });
});
