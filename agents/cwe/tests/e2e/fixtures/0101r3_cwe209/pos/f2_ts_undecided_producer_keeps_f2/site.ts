function classify(body: any, reason: string): { ok: boolean; error?: string } {
  if (!body.email) return { ok: false, error: reason };
  return { ok: true };
}
export async function signup(req, res) {
  const state: any = {};
  try {
    await save(req.body);
  } catch (err) {
    state.error = err.message;
  }
  const v = classify(req.body, state.error);
  if (!v.ok) return res.status(500).json({ error: v.error }); // EXPECT: finding tp-F2-producer-not-literal
}
