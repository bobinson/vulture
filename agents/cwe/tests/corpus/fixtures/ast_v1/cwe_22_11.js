// pins: a dead sanitiser call whose result is discarded (path.basename(p);) leaves p raw, so fs.readFile(p) reports
function handler(req) {
  const p = req.query.f;
  path.basename(p);
  fs.readFile(p, () => {});
}
