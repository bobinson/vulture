try { run() } catch (err) {
  // EXPECT-NEXT: finding  buffer from string
  res.end(Buffer.from(String(err)))
}
