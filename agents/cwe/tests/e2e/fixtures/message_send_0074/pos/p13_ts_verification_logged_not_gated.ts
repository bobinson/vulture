import { sendInviteEmail } from './mail';

export default async function invite(req, res) {
  const ok = verifyWebhookSecret(req);
  console.log('webhook secret ok', ok);
  const email = String(req.body.email || '');
  await sendInviteEmail(email);
  return res.status(200).end();
}
