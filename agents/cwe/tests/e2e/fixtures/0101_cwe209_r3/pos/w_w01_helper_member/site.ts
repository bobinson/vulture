interface Resp { ok: boolean; error?: string }
async function check(id: string, response: Resp): Promise<void> {
  const r = await lookup(id);
  if (!r.ok) {
    response.error = `lookup failed: ${r.error.message}`; // EXPECT: finding tp-W-helper
  }
}
export default async function handler(req, res) {
  const response: Resp = { ok: true };
  await check(req.query.id, response);
  res.status(200).json(response);
}
