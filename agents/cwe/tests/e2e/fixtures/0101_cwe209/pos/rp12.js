app.get("/x", (req, res) => {
  db.query(q, (err, rows) => {
    // EXPECT-NEXT: finding
    if (err) return res.status(500).json({ sql: err.sqlMessage })
  })
})
