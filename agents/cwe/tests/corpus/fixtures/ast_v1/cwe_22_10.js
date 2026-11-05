// pins: a local function named basename that returns its argument unchanged is not a sanitiser (local def wins)
function basename(s) {
  return s;
}
function handler(req) {
  fs.readFile(basename(req.query.f), () => {});
}
