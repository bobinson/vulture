function validate(body: any): { ok: boolean; error?: string } {
  if (!body.email) return { ok: false, error: "email is required" };
  return { ok: true };
}
export async function signup(req, res) {
  const audit: any = {};
  try {
    await save(req.body);
  } catch (err) {
    audit.error = err;
    logger.warn(audit);
  }
  const v = validate(req.body);
  if (!v.ok) return res.status(400).json({ error: v.error }); // EXPECT: clean literal-producer-decides
  res.json({ ok: true });
}
