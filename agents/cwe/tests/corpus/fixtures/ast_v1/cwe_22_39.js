// pins: decodeURIComponent turns %2e%2e%2f back into ../, so it is not a sanitiser (rule 15 pass-through) and fs.readFile(p) reports
function handler(req) {
  const p = decodeURIComponent(req.query.f);
  fs.readFile(p, () => {});
}
