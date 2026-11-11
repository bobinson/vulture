import fs from "node:fs";

// A utility wrapper: every caller builds the path it passes.
export function isFresh(filePath: string, maxAgeMs: number): boolean {
  const info = fs.statSync(filePath); // EXPECT: clean check=cwe.input_validation.path_traversal
  return Date.now() - info.size < maxAgeMs;
}
