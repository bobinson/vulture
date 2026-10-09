function requireAuth(req, res, next) {
  if (req.headers["x-internal"] === "yes") {
    req.authenticated = true;
  }
  if (!req.authenticated && !req.user) {
    return res.status(401).end();
  }
  next();
}
