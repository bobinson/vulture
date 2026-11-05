// pins: a numeric coercion of the request value (Number(...)) only indexes a constant list, so fs.readFile yields nothing (numeric -> constant)
const DOCS = ["a.txt", "b.txt"];
function handler(req) {
  fs.readFile(DOCS[Number(req.query.i)], () => {});
}
