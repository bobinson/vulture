export function h(req, res) {
  const err = new NotFoundError('User not found')
  // EXPECT-NEXT: clean  constructed fixed error
  return res.status(404).json({ error: err.message })
}
