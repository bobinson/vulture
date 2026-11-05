// pins: tagged-template shell, a bare dollar-sign tag applied to a template literal that interpolates a request field (positive)
function handler(req, res) {
  const dir = req.query.dir;
  $`rm -rf ${dir}`;
}
