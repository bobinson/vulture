import { sendMagicLinkEmail } from './mail';

async function startLink(linkQuery) {
  const email = String(linkQuery.email || '');
  await sendMagicLinkEmail(email);
}

export default async function handler(req, res) {
  await startLink(req.query);
  return res.status(202).end();
}
