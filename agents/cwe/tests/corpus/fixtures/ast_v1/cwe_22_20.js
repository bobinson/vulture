// pins: raw U+2028 characters inside a string literal before the sink - newline-only numbering keeps line_start and snippet aligned (D21)
function handler(req) {
  const banner = "left middle right";
  const p = req.query.f;
  fs.readFile(p, () => {});
}
