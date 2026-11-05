// CWE-918 sanitiser on the wrong variable: allowedHost() cleans req.query.host while the unsanitised req.query.url is fetched.
async function handler(req, res) {
  const target = req.query.url;
  const host = allowedHost(req.query.host);
  const reply = await fetch(target);
  res.end(await reply.text());
}

module.exports = handler;
