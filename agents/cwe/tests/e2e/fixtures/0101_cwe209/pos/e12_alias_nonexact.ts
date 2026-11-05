try { run() } catch (e2) {
  const errorObj = e2
  // EXPECT-NEXT: finding  alias nonexact
  res.status(500).send(errorObj)
}
