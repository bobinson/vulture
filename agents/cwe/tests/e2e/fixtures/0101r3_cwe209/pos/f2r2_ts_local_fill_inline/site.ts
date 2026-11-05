function validate(body: any): { ok: boolean; error?: string } {
  if (!body.email) return { ok: false, error: "email is required" };
  return { ok: true };
}
export async function signup(req, res) {
  const v = validate(req.body);
  try { await persist(req.body); } catch (e: any) { v.ok = false; v.error = e.message; }
  if (!v.ok) return res.status(400).json({ error: v.error }); // EXPECT: finding tp-local-fill-overrides-literal-producer
  res.json({ ok: true });
}
