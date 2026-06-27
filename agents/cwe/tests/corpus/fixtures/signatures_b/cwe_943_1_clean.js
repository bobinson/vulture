app.get("/search", (req, res) => {
  // Safe: numeric cast + $eq equality, no operator injection.
  db.collection("users").find({ age: { $eq: Number(req.query.age) } });
});
