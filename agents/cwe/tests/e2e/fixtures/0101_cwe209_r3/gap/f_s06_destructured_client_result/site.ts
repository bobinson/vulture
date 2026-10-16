export async function list(req, res) {
  const { data, error } = await db.from('notes').select();
  if (error) return res.status(500).json({ error }); // EXPECT: clean ambiguous-library-error-object
  res.json(data);
}
