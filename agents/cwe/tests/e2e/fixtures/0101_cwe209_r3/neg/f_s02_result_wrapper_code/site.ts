async function loadLedger(id: string) {
  try {
    return { ok: true, rows: await store.read(id) };
  } catch (err) {
    console.error('ledger read failed', { error: err.message });
    return { ok: false, error: 'LEDGER_UNAVAILABLE' };
  }
}
export async function showLedger(req, res) {
  const outcome = await loadLedger(req.query.id);
  if (!outcome.ok) return res.status(503).json({ error: outcome.error }); // EXPECT: clean clean
  res.json(outcome.rows);
}
