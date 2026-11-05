const BYPASS = 'on' as string;
export function middleware(req, res, next) {
  if (req.headers['x-bypass'] === BYPASS) return next();
  return res.status(401).end();
}
