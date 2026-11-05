// pins: an environment value is operator-controlled - process.env.DOC_PATH reaches fs.readFile, but env reports for no family (none)
function handler() {
  fs.readFile(process.env.DOC_PATH, () => {});
}
