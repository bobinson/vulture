// pins: a parameter named like a file (filename) of unknown origin is the lifted parameter-name heuristic source (R-T, hint:param)
function show(filename) {
  fs.readFile(filename, () => {});
}
