export async function h(req, res) {
  const { data, error } = await db.from('t').select()
  // EXPECT-NEXT: clean  destructured error from a query result
  if (error) return res.status(400).json({ error })
  res.json(data)
}
