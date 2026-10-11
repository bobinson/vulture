try { run() } catch (err) {
  // EXPECT-NEXT: finding  stack arm on a peer write
  res.status(500).json({ trace: err.stack })
}
