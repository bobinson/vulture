// pins: three hops - a destructured request field (names), a loop target (name) and a concatenation (full) reach fs.readFile
function handler(req) {
  const { names } = req.body;
  for (const name of names) {
    const full = "/srv/docs/" + name;
    fs.readFile(full, () => {});
  }
}
