// pins: a rest element of a destructured request body stays external (reports) while the sibling leaf passes slugify (declines)
function handler(req) {
  const { name, ...rest } = req.body;
  fs.readFile(slugify(name), () => {});
  fs.readFile(rest.extra, () => {});
}
