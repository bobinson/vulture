import { existsSync } from "node:fs";

export function present(filePath) {
  return existsSync(filePath); // EXPECT: clean check=cwe.input_validation.path_traversal
}
