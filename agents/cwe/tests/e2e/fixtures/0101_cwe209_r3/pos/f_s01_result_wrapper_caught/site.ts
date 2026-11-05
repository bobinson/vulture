async function loadLedger(id: string) {
  try {
    return { ok: true, rows: await store.read(id) };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  }
}
export async function showLedger(req, res) {
  const outcome = await loadLedger(req.query.id);
  if (!outcome.ok) return res.status(500).json({ error: outcome.error }); // EXPECT: finding tp
  res.json(outcome.rows);
}
