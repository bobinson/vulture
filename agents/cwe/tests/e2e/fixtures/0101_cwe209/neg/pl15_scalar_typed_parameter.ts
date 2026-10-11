function h(res, error: string) {
  // EXPECT-NEXT: clean  scalar-typed parameter
  res.status(400).json({ error })
}
