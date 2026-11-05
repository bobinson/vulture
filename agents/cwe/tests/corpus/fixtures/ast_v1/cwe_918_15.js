// CWE-918 iteration callback: each element of the req.body.urls array reaches fetch through the forEach callback's parameter.
function handler(req, res) {
  const urls = req.body.urls;
  urls.forEach((u) => fetch(u));
  res.end();
}

module.exports = handler;
