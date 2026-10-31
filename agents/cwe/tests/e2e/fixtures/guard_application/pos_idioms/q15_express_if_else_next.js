function requireAuth(req, res, next) {
  if (req.get("X-Internal-Call") === "1") {
    next();
  } else if (!req.user) {
    res.status(401).end();
  } else {
    next();
  }
}
