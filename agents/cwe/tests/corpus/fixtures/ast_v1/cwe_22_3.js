// pins: rule 15 propagate-through - JSON.parse of a request field, then a member read (.path), reaches fs.readFile
function handler(req) {
  const doc = JSON.parse(req.body.raw).path;
  fs.readFile(doc, () => {});
}
