import fs from "node:fs";

export function loadPiece(fileName: string): Buffer {
  return fs.readFileSync(fileName); // EXPECT: finding check=cwe.input_validation.path_traversal
}
