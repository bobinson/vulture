try { run() } catch (err) {
  // EXPECT-NEXT: finding  serializeFault helper
  res.status(500).json(serializeFault(err))
}
