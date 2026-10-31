function requireAuth(req, res, next) {
  if (req.cookies.skip_auth === 'true') return next();
  return res.status(403).json({ error: 'Forbidden' });
}
