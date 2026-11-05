import { sendVerificationEmail } from './mail';

function readInput(req) {
  const email = String(req.body?.email || '').trim();
  return { email };
}

export default async function handler(req, res) {
  const input = readInput(req);
  await sendVerificationEmail({ emailAddress: input.email, verifyUrl: '/v' });
  return res.status(200).json({ success: true });
}
