import { sendReceiptEmail } from './mail';

export default async function onPayment(req, res) {
  if (!verifyHookToken(req)) {
    return res.status(401).end();
  }
  const email = String(req.body.data.email || '');
  await sendReceiptEmail(email, req.body.data.amount);
  return res.status(204).end();
}
