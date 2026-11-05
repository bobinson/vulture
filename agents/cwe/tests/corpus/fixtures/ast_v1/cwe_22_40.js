// pins: replace("..", "") is a bypassable strip, not a sanitiser (rule 15 pass-through), so fs.readFile reports
function handler(req) {
  const p = req.query.f.replace("..", "");
  fs.readFile("/srv/docs/" + p, () => {});
}
