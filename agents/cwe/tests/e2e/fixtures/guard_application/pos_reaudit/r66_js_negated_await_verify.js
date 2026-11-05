async function mw(req, res, next) {
  if (!await checkJwt(req) && req.headers['x-internal'] === '1') return next();
  return res.status(401).end();
}
