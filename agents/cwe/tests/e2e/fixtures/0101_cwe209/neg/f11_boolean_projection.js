db.query(sql, (err, rows) => {
  // EXPECT-NEXT: clean  boolean projection
  res.json({ ok: !err, count: rows.length })
})
