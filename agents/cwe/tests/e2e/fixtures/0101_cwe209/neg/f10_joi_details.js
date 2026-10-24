function h(req, res) {
  const { error } = schema.validate(req.body)
  // EXPECT-NEXT: clean  joi details
  if (error) return res.status(400).json({ message: error.details[0].message })
}
