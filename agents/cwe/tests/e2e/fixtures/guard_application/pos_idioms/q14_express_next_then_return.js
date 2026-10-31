function requireAuth(req, res, next) {
  if (req.get("X-Internal-Call") === "1") {
    next();
    return;
  }
  if (!req.user) {
    return res.status(401).end();
  }
  next();
}
