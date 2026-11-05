try { run() } catch (err) {
  err = coerceFault(err)
  // EXPECT-NEXT: finding  rebind normalise
  res.status(500).json(err)
}
