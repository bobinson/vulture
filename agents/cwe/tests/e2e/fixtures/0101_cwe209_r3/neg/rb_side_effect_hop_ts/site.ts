import { charge } from "./billing";

async function topUp(userId: string) {
  let note: string | null = null;
  try {
    await charge(userId);
  } catch (error) {
    note = String(error);
  }
  await audit.insert({ userId, note });
}

async function process(userId: string) {
  await topUp(userId);
  const r = await charge(userId);
  return { ok: r.ok, error: r.ok ? null : "PAYMENT_DECLINED" };
}

export default async function handler(req: any, res: any) {
  const out = await process(req.body.userId);
  if (!out.ok) return res.status(402).json({ error: out.error }); // EXPECT: clean clean-n04-with-unrelated-hop
}
