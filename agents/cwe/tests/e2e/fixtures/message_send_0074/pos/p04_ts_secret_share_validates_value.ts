import { sendSecretLinkEmail } from './mail';

export default async function share(req, res) {
  const secret = String(req.body.secret || '');
  if (!validateSecret(secret)) {
    return res.status(400).json({ error: 'invalid' });
  }
  const link = await storeOnce(secret);
  const recipientEmail = String(req.body.recipientEmail || '');
  await sendSecretLinkEmail(recipientEmail, link);
  return res.status(201).json({ ok: true });
}
