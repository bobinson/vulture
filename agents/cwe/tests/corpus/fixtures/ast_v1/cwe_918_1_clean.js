// CWE-918 clean twin of cwe_918_1: an early-return hostname allowlist guard on the same variable precedes the fetch.
const ALLOWED_HOSTS = ["api.example.test"];

async function handler(req, res) {
  const target = req.query.url;
  if (!ALLOWED_HOSTS.includes(new URL(target).hostname)) return res.status(400).end();
  const reply = await fetch(target);
  res.end(await reply.text());
}

module.exports = handler;
