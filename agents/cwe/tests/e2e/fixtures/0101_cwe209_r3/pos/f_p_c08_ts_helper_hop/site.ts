const fail = (msg: string) => ({ ok: false, error: msg });
async function load(id: string) {
  try { return { ok: true, data: await store.read(id) }; }
  catch (err) { return fail(err.message); }
}
export async function show(req, res) {
  const outcome = await load(req.params.id);
  res.status(500).json({ error: outcome.error }); // EXPECT: finding tp-helper-param
}
