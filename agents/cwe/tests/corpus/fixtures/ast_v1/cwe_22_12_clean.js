// pins: twin of cwe_22_12.js plus an early-exit regex validation guard on opts.file (validate role), so fs.readFile declines
function handler(req) {
  const opts = {};
  opts[req.query.key] = req.query.value;
  if (!/^[a-z0-9_-]+$/.test(opts.file)) return;
  fs.readFile(opts.file, () => {});
}
