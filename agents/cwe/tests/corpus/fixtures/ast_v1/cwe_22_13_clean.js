// pins: a local function named readFile shadows the sink word, so readFile(req.query.f) resolves to it and is not a sink
function readFile(p) {
  return p.length;
}
function handler(req) {
  return readFile(req.query.f);
}
