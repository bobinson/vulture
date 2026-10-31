try { run() } catch (err) {
  // EXPECT-NEXT: finding  driver detail member
  res.status(500).json({ detail: err.sqlDetail })
}
