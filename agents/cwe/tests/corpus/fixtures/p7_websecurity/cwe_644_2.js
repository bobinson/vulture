function banner(req, res) {
  res.send("<p>" + req.headers["x-forwarded-for"] + "</p>");
}
