import { store } from './store';
import { sendLoginLinkEmail } from './mail';
import { isValidEmail } from './validators';

export default async function handler(req, res) {
  const body = req.body ?? {};
  const email = String(body.email || '').trim().toLowerCase();
  if (!isValidEmail(email)) {
    return res.status(200).json({ success: true });
  }
  const allowed = await store.allowStart({
    email,
    perEmailLimit: 3,
    windowSeconds: 60,
  });
  if (!allowed) {
    return res.status(200).json({ success: true });
  }
  await sendLoginLinkEmail(email, await store.createToken(email));
  return res.status(200).json({ success: true });
}
