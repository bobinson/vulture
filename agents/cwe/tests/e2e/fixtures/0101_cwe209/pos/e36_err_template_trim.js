try { run() } catch (err) {
  // EXPECT-NEXT: finding  err template trim
  res.send(`failed: ${err}`.trim())
}
