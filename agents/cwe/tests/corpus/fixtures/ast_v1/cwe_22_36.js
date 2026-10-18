// pins: a closure nested two deep reads the join of every def of p in its enclosing function (R-O), so a later p = req.query.f reaches it
function handler(req) {
  let p = "index.html";
  setTimeout(() => {
    process.nextTick(() => fs.readFile(p, () => {}));
  }, 10);
  p = req.query.f;
}
