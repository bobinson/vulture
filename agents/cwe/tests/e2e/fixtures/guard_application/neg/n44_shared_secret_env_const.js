const INTERNAL_TOKEN = process.env.INTERNAL_TOKEN;
function svc(req, res, next) {
  if (req.headers['x-internal-token'] === INTERNAL_TOKEN) {
    return next();
  }
  return res.status(401).end();
}
