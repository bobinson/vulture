function load(id: string) {
  try { return { ok: true, data: store.read(id) }; }
  catch (err) { return { ok: false, error: err.message }; }
}
function fill(resp, id: string) {
  const r = load(id);
  if (!r.ok) { resp.error = r.error; } // EXPECT: finding tp-W-through-F
}
export function handler(req, res) {
  const out: any = {};
  fill(out, req.query.id);
  res.json(out);
}
