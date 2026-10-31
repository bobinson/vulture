import type { NextApiRequest, NextApiResponse } from 'next';
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const response: { ok: boolean; error?: string } = { ok: false };
  try {
    await doIt();
  } catch (e) {
    response.error = `failed: ${(e as Error).message}`; // EXPECT: finding
  }
  return res.status(200).json(response);
}
