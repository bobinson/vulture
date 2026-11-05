import { sendWelcomeEmail } from './mail';

export default async function onUserCreated(req, res) {
  if (!verifyWebhookSecret(
    req,
    process.env.HOOK_SECRET,
  )) return res.status(401).end();
  const { email } = req.body.event.data.new;
  await sendWelcomeEmail(email);
  return res.status(200).end();
}
