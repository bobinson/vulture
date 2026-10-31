async function load(id: string) {
  try { return { ok: true, data: await store.read(id) }; }
  catch (err) { return { ok: false, error: err.message }; }
}
export async function show(req, res) {
  const { error: loadError } = await load(req.params.id);
  res.status(500).json({ message: loadError }); // EXPECT: finding tp-renamed-destructure
}
