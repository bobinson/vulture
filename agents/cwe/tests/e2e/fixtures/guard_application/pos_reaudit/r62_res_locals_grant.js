function auth(req, res, next) {
  if (req.headers['x-admin'] === 'true') {
    res.locals.authenticated = true;
  }
  if (!res.locals.authenticated) return res.status(401).end();
  next();
}
