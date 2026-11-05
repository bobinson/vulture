import type { NextApiRequest, NextApiResponse } from 'next';
import { getStatus } from '@/lib/q';
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const status = await getStatus(String(req.query.id));
  return res.status(200).json({ state: status.state, ...(status.error ? { error: 'FAILED', message: status.error } : {}) }); // EXPECT: finding
}
