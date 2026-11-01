// pins: Object.assign(cfg, req.body) merges request fields into cfg (R-J), so cfg.path reaches fs.readFile
function handler(req) {
  const cfg = { path: "index.html" };
  Object.assign(cfg, req.body);
  fs.readFile(cfg.path, () => {});
}
