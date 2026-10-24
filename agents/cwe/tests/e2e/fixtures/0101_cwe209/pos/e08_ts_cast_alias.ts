try { run() } catch (err) {
  const errorMessage = (err as Error).message
  // EXPECT-NEXT: finding  ts cast alias
  res.status(500).json({ error: errorMessage })
}
