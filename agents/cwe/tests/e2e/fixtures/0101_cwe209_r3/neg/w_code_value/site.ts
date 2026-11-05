export async function handler(req: any, res: any) {
  const out: any = { ok: true };
  try { await run(); } catch (err) {
    out.error = err.code; // EXPECT: clean clean-W-code-value
  }
  res.json(out);
}
