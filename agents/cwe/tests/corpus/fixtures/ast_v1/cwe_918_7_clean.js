// CWE-918 clean: the fetched URL is operator config (an env value with a constant default); no request input reaches fetch.
async function handler(req, res) {
  const target = process.env.STATUS_URL || "http://localhost/health";
  const reply = await fetch(target);
  res.end(await reply.text());
}

module.exports = handler;
