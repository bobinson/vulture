export function h(req, res) {
  // EXPECT-NEXT: clean  catalog class message
  return res.status(400).json({ message: ValidationError.MISSING_EMAIL.message })
}
