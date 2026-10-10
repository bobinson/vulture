import { getSession } from './auth';
import { sendLoginLinkEmail } from './mail';

export default async function handler(req, res) {
  const session = await getSession(req);
  if (!session) {
    return res.status(401).end();
  }
  const email = String(req.body.email || '').trim();
  await sendLoginLinkEmail(email, 'token');
  return res.status(200).json({ success: true });
}
