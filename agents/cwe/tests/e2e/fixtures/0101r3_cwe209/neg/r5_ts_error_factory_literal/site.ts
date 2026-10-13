import { Result } from "./result";
function validate(body: any) {
  try { parse(body); return Result.ok(); }
  catch (e: any) { logger.warn(e); return Result.fail("INVALID_BODY"); }
}
export async function signup(req, res) {
  const v = validate(req.body);
  if (!v.ok) return res.status(400).json({ error: v.error }); // EXPECT: clean error-factory-literal
  res.json({ ok: true });
}
