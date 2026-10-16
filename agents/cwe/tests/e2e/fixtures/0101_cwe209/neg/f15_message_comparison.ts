try { run() } catch (err) {
  // EXPECT-NEXT: clean  message comparison
  res.status(400).json({ error: err.message.includes('duplicate') ? 'Already exists' : 'Failed' })
}
