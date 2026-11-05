// CWE-918 two-statement flow: req.query.url is bound to a local, then fetched; the host allowlist is never consulted.
const ALLOWED_HOSTS = ["api.example.test"];

async function handler(req, res) {
  const target = req.query.url;
  const reply = await fetch(target);
  res.end(await reply.text());
}

module.exports = handler;
