function render(req, res) {
  const role = req.session.role;
  res.render("menu", { role });
}
