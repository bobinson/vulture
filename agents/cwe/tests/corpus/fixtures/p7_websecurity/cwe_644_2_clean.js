function banner(req, res) {
  res.send(JSON.stringify({ via: req.headers["x-forwarded-for"] }));
}
