export function createNote(req, res) {
  const verdict = noteSchema.validate(req.body);
  // EXPECT-NEXT: finding  known-gap the assigned form of a validation result is judged by name (as zod f09); only the destructured form (f10) is clean
  if (verdict.error) return res.status(400).json({ message: verdict.error.message });
  res.status(201).end();
}
