try { run() } catch (err) {
  // EXPECT-NEXT: clean  commented out
  // res.status(500).json({ error: err.message })
  res.status(500).json({ error: 'Internal' })
}
