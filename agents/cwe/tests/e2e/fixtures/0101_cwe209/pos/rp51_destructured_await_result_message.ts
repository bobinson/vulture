export async function showAccount(req, res) {
  const { data, error } = await loadAccountById(req.query.uid);
  // EXPECT-NEXT: finding  destructured result error, its message reaches the peer
  if (error) return res.status(500).json({ message: error.message });
  return res.json(data);
}
