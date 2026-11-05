try { run() } catch (err) {
  // EXPECT-NEXT: finding  known-gap sanitise wrapper
  res.status(500).json({ error: toPublicMessage(err.message) })
}
