export function internalOnly(
  sharedKey = 'local-dev',
  options = {},
) {
  return (req, res, next) => {
    if (req.headers['x-internal-key'] === sharedKey) return next();
    return res.status(401).end();
  };
}
