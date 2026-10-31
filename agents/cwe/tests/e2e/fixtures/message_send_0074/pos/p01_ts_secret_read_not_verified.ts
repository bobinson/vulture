import { sendLoginLinkEmail } from './mail';

export default async function handler(req, res) {
  const secret = req.body.secret;
  if (!secret) {
    return res.status(400).json({ error: 'missing' });
  }
  const email = String(req.body.email || '');
  await sendLoginLinkEmail(email, secret);
  return res.status(200).json({ ok: true });
}
