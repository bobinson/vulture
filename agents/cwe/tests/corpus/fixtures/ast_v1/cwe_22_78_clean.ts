// pins: a callback's file-named parameter has no parameter-name hint - a nested callback is no entry function (R-T, D23), so fileName takes R-B's receiver, pendingEntries, which no Def binds, and fs.readFileSync reports nothing (negative)
import fs from "node:fs";

export function readEntry(): Buffer[] {
  return pendingEntries.map((fileName: string) => fs.readFileSync(fileName));
}

export function readDefaults(): Buffer[] {
  return readEntry();
}
