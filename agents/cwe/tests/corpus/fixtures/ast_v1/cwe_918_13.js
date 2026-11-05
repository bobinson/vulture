// CWE-918 constant base + external path: a constant base URL concatenated with req.query.page is fetched.
const API_BASE = "http://localhost:9000/";

async function handler(req, res) {
  const reply = await fetch(API_BASE + req.query.page);
  res.end(await reply.text());
}

module.exports = handler;
