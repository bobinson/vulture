try { run() } catch (err) {
  const errorJson = JSON.stringify(err, null, 2)
  // EXPECT-NEXT: finding  stringify pretty
  res.status(500).send(errorJson)
}
