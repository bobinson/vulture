import { statSync } from "node:fs";

export function weigh(fileName: string) {
  return statSync(fileName).size; // EXPECT: clean check=cwe.input_validation.path_traversal
}
