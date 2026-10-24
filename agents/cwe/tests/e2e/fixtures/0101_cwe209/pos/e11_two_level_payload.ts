try { run() } catch (err) {
  const msg = err.message
  const errorPayload = { message: msg }
  // EXPECT-NEXT: finding  two level payload
  res.status(500).json(errorPayload)
}
