// pins: an exported helper's file-named parameter keeps the parameter-name hint even though its own file calls it - an exported function is an entry function (R-T, D23), so fileName reaching fs.readFileSync reports (positive)
import fs from "node:fs";

export function readEntry(fileName: string): Buffer {
  return fs.readFileSync(fileName);
}

export function readDefaults(): Buffer {
  return readEntry("defaults.json");
}
