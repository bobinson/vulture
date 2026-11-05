// pins: a dynamic-key write (opts[req.query.key] = req.query.value) then a field read (opts.file) reaches fs.readFile
function handler(req) {
  const opts = {};
  opts[req.query.key] = req.query.value;
  fs.readFile(opts.file, () => {});
}
