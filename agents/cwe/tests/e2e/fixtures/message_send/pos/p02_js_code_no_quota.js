const mailer = require('./mailer');

async function requestCode(req, res) {
  const { email } = req.body;
  const code = Math.floor(100000 + Math.random() * 900000);
  await mailer.sendCodeEmail({ to: email, code });
  res.json({ ok: true });
}

module.exports = { requestCode };
