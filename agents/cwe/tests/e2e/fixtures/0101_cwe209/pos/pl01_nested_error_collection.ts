try { run() } catch (err) {
  // EXPECT-NEXT: finding  nested error collection
  res.status(500).json({ issues: err.errors })
}
