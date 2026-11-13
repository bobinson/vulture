import fs from "node:fs";

function present(p: string): boolean {
  return fs.existsSync(p); // EXPECT: finding check=cwe.input_validation.path_traversal
}

// A utility wrapper: every caller builds the path it passes.
export function ensureSheet(filePath: string): void {
  if (!present(filePath)) {
    fs.appendFileSync(filePath, "{}"); // EXPECT: finding check=cwe.input_validation.path_traversal
  }
}
