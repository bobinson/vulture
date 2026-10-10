const sms = require('./sms');

async function inbound(req, res) {
  if (!verifySignature(req)) {
    return res.status(403).end();
  }
  await sms.sendSmsReply({ to: req.body.From, text: 'Thanks' });
  res.status(204).end();
}

module.exports = { inbound };
