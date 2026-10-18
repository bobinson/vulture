// pins: an unconditional reassignment to a constant overwrites the request value before fs.readFile(p)
function handler(req) {
  let p = req.query.f;
  p = "index.html";
  fs.readFile(p, () => {});
}
