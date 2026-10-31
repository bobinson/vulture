async function load(id: string) {
  try { return { ok: true, data: await store.read(id) }; }
  catch (err) { return { ok: false, error: process.env.NODE_ENV !== 'production' ? err.message : 'internal' }; }
}
export async function show(req, res) {
  const outcome = await load(req.params.id);
  res.status(500).json({ error: outcome.error }); // EXPECT: finding clean-envguard
}
