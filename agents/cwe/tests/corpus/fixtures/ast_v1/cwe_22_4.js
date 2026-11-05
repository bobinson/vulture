// pins: the sink sits in a same-file callee - readIt(req.query.f) binds p, and fs.readFile(p) inside readIt reports
function readIt(p) {
  return fs.readFile(p, () => {});
}
function handler(req) {
  return readIt(req.query.f);
}
