import { sendWelcomeEmail } from './mail';
import { requireValidHookSecret } from './guards';

export default async function onUserCreated(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).end();
  }
  if (!requireValidHookSecret(req, res)) return;
  const { email, name } = req.body.event.data.new;
  await sendWelcomeEmail(email, name);
  return res.status(200).json({ ok: true });
}
