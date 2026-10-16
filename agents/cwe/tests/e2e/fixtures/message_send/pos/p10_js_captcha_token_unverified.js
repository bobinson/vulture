const mailer = require('./mailer');

async function subscribe(req, res) {
  const { email, captchaToken } = req.body;
  console.log('captcha token present', Boolean(captchaToken));
  await mailer.sendConfirmationEmail({ to: email });
  res.json({ ok: true });
}

module.exports = { subscribe };
