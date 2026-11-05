// pins: this.load(...) resolves to the load method of the enclosing class (R-F), whose fs.readFile(p) is the sink
class DocService {
  load(p) {
    return fs.readFile(p, () => {});
  }
  handle(req) {
    return this.load(req.query.f);
  }
}
