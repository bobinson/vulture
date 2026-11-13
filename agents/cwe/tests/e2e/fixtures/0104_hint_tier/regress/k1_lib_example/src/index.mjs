import { appendFileSync } from "node:fs";
import { join } from "node:path";

const ROOT = process.cwd();

export function keepCrate(fileName, data) {
  appendFileSync(join(ROOT, "crates", fileName), data); // EXPECT: finding check=cwe.input_validation.path_traversal
}
