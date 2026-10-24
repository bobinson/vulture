app.use((err, req, res, next) => {
  // EXPECT-NEXT: finding  known-gap expose guard
  res.status(err.status || 500).json({ error: err.expose ? err.message : 'Internal Server Error' })
})
