// pins: the sink sits INSIDE the branch of an allowlist test (ALLOWED.includes(name)) on the same value, so fs.readFile declines
const ALLOWED = ["a.txt", "b.txt"];
function handler(req) {
  const name = req.query.f;
  if (ALLOWED.includes(name)) {
    fs.readFile(name, () => {});
  }
}
