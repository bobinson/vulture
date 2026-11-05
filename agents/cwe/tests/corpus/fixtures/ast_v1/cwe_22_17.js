// pins: a trailing syntax error forces whole-file fallback - the regex owner reports fs.readFile(req.query.f) without validation.ast
function handler(req) {
  fs.readFile(req.query.f, () => {});
}
const broken = ;
