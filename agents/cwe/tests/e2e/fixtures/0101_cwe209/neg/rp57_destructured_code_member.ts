export async function syncInvoices(req, res) {
  const { error } = await pushInvoices(req.body.batch);
  // EXPECT-NEXT: clean  a code member of a result error is a projection
  if (error) return res.status(409).json({ code: error.code });
  res.status(204).end();
}
