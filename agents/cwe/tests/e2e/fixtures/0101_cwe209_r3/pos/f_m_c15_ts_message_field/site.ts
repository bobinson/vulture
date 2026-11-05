async function load(id: string) {
  try { return { ok: true, data: await store.read(id) }; }
  catch (err) { return { ok: false, message: err.message }; }
}
export async function show(req, res) {
  const outcome = await load(req.params.id);
  res.status(500).json({ message: outcome.message }); // EXPECT: finding tp-nonerror-fieldname
}
