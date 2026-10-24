const mailer = require('./mailer');

const SUPPORT_EMAIL = 'support@example.com';

async function contact(req, res) {
  const message = String(req.body.message || '');
  await mailer.sendContactEmail({ to: SUPPORT_EMAIL, text: message });
  res.json({ ok: true });
}

module.exports = { contact };
