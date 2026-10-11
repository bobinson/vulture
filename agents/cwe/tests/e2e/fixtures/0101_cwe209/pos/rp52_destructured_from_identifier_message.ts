export async function showLedger(req, res) {
  const outcome = await fetchLedgerRows(req.params.id);
  const { error } = outcome;
  // EXPECT-NEXT: finding  destructured from an unresolved identifier, message written
  if (error) return res.status(502).send(error.message);
  res.json(outcome.rows);
}
