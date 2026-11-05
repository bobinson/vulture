// pins: an arrow function assigned to a const is a same-file function (R-G) - showDoc(req.query.f) reaches its fs.readFile(p)
const showDoc = (p) => fs.readFile(p, () => {});
function handler(req) {
  return showDoc(req.query.f);
}
