// pins: a containment guard on a different variable (other) does not cover the sink argument p, so fs.readFile(p) reports
function handler(req) {
  const root = "/srv/docs/";
  const p = req.query.f;
  const other = path.resolve(root, req.query.g);
  if (!other.startsWith(root)) return;
  fs.readFile(p, () => {});
}
