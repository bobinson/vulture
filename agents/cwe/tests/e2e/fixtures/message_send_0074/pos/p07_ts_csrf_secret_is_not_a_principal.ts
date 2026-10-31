import { sendLoginLinkEmail } from './mail';

export default async function login(req, res) {
  if (!validateCsrfSecret(req)) {
    return res.status(403).end();
  }
  const email = String(req.body.email || '');
  await sendLoginLinkEmail(email);
  return res.status(200).json({ ok: true });
}
