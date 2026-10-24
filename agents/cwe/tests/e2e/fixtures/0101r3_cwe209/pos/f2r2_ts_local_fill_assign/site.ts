function validate(body: any): { ok: boolean; error?: string } {
  if (!body.email) return { ok: false, error: "email is required" };
  return { ok: true };
}
export async function signup(req, res) {
  const v = validate(req.body);
  try {
    await persist(req.body);
  } catch (e: any) {
    Object.assign(v, { ok: false, error: e.message });
  }
  if (!v.ok) return res.status(400).json({ error: v.error }); // EXPECT: finding tp-local-merge-fill
  res.json({ ok: true });
}
