// pins: a path builder alone is not a CWE-22 sink - path.join(root, req.query.f) is only returned, never read or written here
function handler(req) {
  const root = "/srv/docs";
  return path.join(root, req.query.f);
}
