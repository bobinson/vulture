// pins: a depth-3 write (req.query.f = path.basename(...)) never binds its prefix (R-K), so req.query.g still reaches fs.readFile
function handler(req) {
  req.query.f = path.basename(req.query.f);
  fs.readFile(req.query.g, () => {});
}
