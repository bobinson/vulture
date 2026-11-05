import type { NextApiRequest, NextApiResponse } from 'next';
import { resolveThing } from '@/lib/thing';
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const response: { ok: boolean; error?: string } = { ok: false };
  const r = await resolveThing(String(req.query.id));
  if (!r.ok) {
    response.error = `check failed: ${r.error.message}`; // EXPECT: finding
  }
  return res.status(200).json(response);
}
