try { run() } catch (err) {
  // EXPECT-NEXT: clean  ternary literal
  res.status(500).json({ error: err ? 'failed' : null })
}
