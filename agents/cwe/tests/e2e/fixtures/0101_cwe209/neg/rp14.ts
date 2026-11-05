app.post("/x", (req, res) => {
  const { error } = schema.validate(req.body)
  // EXPECT-NEXT: clean
  if (error) return res.status(400).json({ message: error.details[0].message })
})
