export function h(req, res) {
  const err = Errors.TIMEOUT
  // EXPECT-NEXT: clean  constant member binding
  res.status(504).json({ error: err })
}
