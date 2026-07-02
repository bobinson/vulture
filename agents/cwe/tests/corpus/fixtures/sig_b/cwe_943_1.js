// E-commerce product filter endpoint.
// CWE-943: $function operator built from untrusted query string.
app.get("/products", (req, res) => {
  const cmp = req.query.priceFilter;
  Product.find({ $where: "this.price " + cmp }).then((rows) => res.json(rows));
});
