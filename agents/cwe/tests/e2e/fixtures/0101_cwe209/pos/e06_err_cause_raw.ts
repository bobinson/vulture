try { run() } catch (err) {
  // EXPECT-NEXT: finding  err cause raw
  res.status(500).json({ cause: err.cause })
}
