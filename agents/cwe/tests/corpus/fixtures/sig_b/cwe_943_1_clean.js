// E-commerce product filter endpoint.
// Safe: untrusted value cast to Number and compared with a fixed field, no $where.
app.get("/products", (req, res) => {
  const maxPrice = Number(req.query.maxPrice);
  Product.find({ price: { $lte: maxPrice } }).then((rows) => res.json(rows));
});
