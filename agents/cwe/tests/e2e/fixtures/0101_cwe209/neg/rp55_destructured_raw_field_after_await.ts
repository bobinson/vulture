export async function showProfile(req, res) {
  const { data, error } = await loadProfileById(req.query.uid);
  // EXPECT-NEXT: clean  the raw result field is not raw error text (D7, as n04)
  if (error) return res.status(500).json({ error });
  return res.json(data);
}
