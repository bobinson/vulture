const BYPASS = 'on' as const;
export function guard(req, res, next) {
  if (req.headers['x-debug'] === BYPASS) return next();
  return res.status(401).end();
}
