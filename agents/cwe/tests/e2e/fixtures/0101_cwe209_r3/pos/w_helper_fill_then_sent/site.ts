import type { NextApiRequest, NextApiResponse } from 'next';
import { resolveThing } from '@/lib/thing';
interface Out { ok: boolean; error?: string }
async function fill(id: string, response: Out): Promise<void> {
  const r = await resolveThing(id);
  if (!r.ok) {
    console.error('failed', r.error);
    response.error = `check failed: ${r.error.message}`; // EXPECT: finding
  }
}
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const response: Out = { ok: false };
  await fill(String(req.query.id), response);
  return res.status(200).json(response);
}
