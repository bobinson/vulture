function validate(body: any): { ok: boolean; error?: string } {
  if (!body.email) return { ok: false, error: "email is required" };
  return { ok: true };
}
export async function signup(req, res) {
  const v = validate(req.body);
  const audit: any = {};
  try {
    await persist(req.body);
  } catch (e: any) {
    audit.error = e.message;
    logger.warn(audit);
  }
  if (!v.ok) return res.status(400).json({ error: v.error }); // EXPECT: clean fill-on-another-root
  res.json({ ok: true });
}
