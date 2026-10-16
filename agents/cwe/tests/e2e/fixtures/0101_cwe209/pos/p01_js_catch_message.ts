try { f() } catch (err) {
  // EXPECT-NEXT: finding  js catch message
  res.status(500).json({ error: err.message })
}
