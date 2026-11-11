import fs from "node:fs";

const CRATE_ROOT = "/srv/crates";

export function hasCrate(filePath: string): boolean {
  if (!filePath.startsWith(CRATE_ROOT)) {
    throw new Error("outside the crate root");
  }
  return fs.existsSync(filePath); // EXPECT: clean check=cwe.input_validation.path_traversal
}
