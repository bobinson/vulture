app.get("/calc", (req, res) => {
  res.send(`result: ${eval(req.query.x)}`); // EXPECT: finding
});
