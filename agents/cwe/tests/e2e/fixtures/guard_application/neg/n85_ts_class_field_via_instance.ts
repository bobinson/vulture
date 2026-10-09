class AppConfig {
  internalKey = 'dev-key';
}
const config = loadConfig(AppConfig);

export function internal(req, res, next) {
  if (req.headers['x-internal-key'] === config.internalKey) return next();
  return res.status(401).end();
}
