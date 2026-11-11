import fs from "node:fs";
import path from "node:path";

const STORE = "/srv/app/crates";

export function readOwnFile(filePath: string): Buffer {
  return fs.readFileSync(path.join(STORE, filePath)); // EXPECT: finding check=cwe.input_validation.path_traversal
}
