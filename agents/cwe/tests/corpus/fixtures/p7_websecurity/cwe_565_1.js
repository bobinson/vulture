function render(req, res) {
  const role = req.cookies.role;
  res.render("menu", { role });
}
