export async function listOrders(req, res) {
  const { data, error } = await loadOrders(req.query.cursor);
  if (error) return res.status(500).end();
  // EXPECT-NEXT: clean  a sibling field's member is not error detail
  res.json({ rows: data.items, next: data.cursor });
}
