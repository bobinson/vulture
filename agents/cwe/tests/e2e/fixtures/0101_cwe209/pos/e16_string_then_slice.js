try { run() } catch (err) {
  // EXPECT-NEXT: finding  string then slice
  res.status(500).send(String(err).slice(0, 500))
}
