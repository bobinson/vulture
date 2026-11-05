import { Result } from "./result";
function validate(body: any) {
  try { parse(body); return Result.ok(); }
  catch (e: any) { return Result.track(e.message); }
}
export async function signup(req, res) {
  const v = validate(req.body);
  if (!v.ok) return res.status(400).json({ error: v.error }); // EXPECT: clean not-an-error-role-factory
  res.json({ ok: true });
}
