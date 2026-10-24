try { run() } catch (err) {
  // EXPECT-NEXT: finding  spread raw err
  res.status(500).json({ ...err })
}
