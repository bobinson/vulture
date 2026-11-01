// CWE-918 URL-shape checks are not host guards: an isURL check and startsWith("http") early return still let any host reach fetch.
async function handler(req, res) {
  const target = req.query.url;
  if (!validator.isURL(target) || !target.startsWith("http")) return res.status(400).end();
  const reply = await fetch(target);
  res.end(await reply.text());
}

module.exports = handler;
