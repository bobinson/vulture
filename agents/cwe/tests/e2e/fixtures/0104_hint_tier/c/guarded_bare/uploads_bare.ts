import fs from "node:fs";

export function hasCrateUnchecked(filePath: string): boolean {
  return fs.existsSync(filePath); // EXPECT: clean check=cwe.input_validation.path_traversal
}
