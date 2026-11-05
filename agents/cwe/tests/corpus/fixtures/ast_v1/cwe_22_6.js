// pins: a partial sanitiser - path.basename covers a but not b in fs.readFile(dir + path.basename(a) + "/" + b)
function handler(req) {
  const dir = "/srv/docs/";
  const a = req.query.a;
  const b = req.query.b;
  fs.readFile(dir + path.basename(a) + "/" + b, () => {});
}
