import { getServerSession } from './auth';
import { sendVerificationEmail } from './mail';

async function validateRequest(req, res) {
  const session = await getServerSession(req, res);
  const userId = session?.user?.userId;
  if (!userId) {
    res.status(401).end();
    return null;
  }
  const email = String(req.body?.email || '').trim();
  return { userId, email };
}

async function handler(req, res) {
  const input = await validateRequest(req, res);
  if (!input) return;
  await sendVerificationEmail({ emailAddress: input.email, verifyUrl: '/v' });
  return res.status(200).json({ success: true });
}

export default handler;
