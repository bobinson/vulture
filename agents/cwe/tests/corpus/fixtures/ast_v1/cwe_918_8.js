// CWE-918 client-instance chain: req.query.url is passed positionally to get() on the result of a create({...}) call.
async function handler(req, res) {
  const target = req.query.url;
  const reply = await apiClient.create({ timeout: 2000 }).get(target);
  res.end(reply.data);
}

module.exports = handler;
