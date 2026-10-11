app.use((err, req, res, next) => {
  // EXPECT-NEXT: finding  js err-first mw
  res.status(500).json(err)
})
