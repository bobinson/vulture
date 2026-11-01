// pins: a renamed leaf destructured from a require() call carries the imported symbol's words (R-H) - rd is readFile
const { readFile: rd } = require("fs");
function handler(req) {
  rd(req.query.f, () => {});
}
