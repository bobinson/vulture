function parsePayload(raw) {
  try { return { ok: true, value: JSON.parse(raw) }; } catch (e) { return { ok: false, error: e.message }; }
}
function readPayload(raw) {
  const parsed = parsePayload(raw);
  if (!parsed.ok) return { ok: false, error: parsed.error };
  return parsed;
}
export function hook(req, res) {
  const body = readPayload(req.rawBody);
  if (!body.ok) return res.end(body.error); // EXPECT: finding tp
}
