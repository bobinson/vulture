try { f() } catch (err) {
  // EXPECT-NEXT: clean  code field
  res.status(400).json({ error: err.code });
}
