import { sendInviteEmail } from './mail';
import type { InviteQueryData } from './types';

async function deliver(data: InviteQueryData) {
  await sendInviteEmail(data.email);
}

export async function handler(req, res) {
  const input = { email: String(req.query.email) };
  await deliver(input);
  res.end();
}
