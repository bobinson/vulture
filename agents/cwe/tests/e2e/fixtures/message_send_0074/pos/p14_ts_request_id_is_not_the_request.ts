import { sendSecretLinkEmail } from './mail';

export default async function share(req, res) {
  const secret = String(req.body.secret || '');
  const requestId = String(req.headers['x-request-id']);
  if (!validateSecret(secret, requestId)) {
    return res.status(400).json({ error: 'invalid' });
  }
  await sendSecretLinkEmail(String(req.body.recipientEmail), await storeOnce(secret));
  return res.status(201).end();
}
