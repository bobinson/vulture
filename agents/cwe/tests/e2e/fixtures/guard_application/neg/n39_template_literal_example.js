const example = `
function auth(req, res, next) {
  if (req.headers['x-internal'] === '1') {
    return next();
  }
  if (!req.user) return res.status(401).end();
  next();
}
`;
module.exports = { example };
