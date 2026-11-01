// pins: rebinding a sink chain (fs.readFile = wrapper) marks it dynamic, and a later fs.readFile(req.query.f) still reports
fs.readFile = wrapper;
function handler(req) {
  fs.readFile(req.query.f, () => {});
}
