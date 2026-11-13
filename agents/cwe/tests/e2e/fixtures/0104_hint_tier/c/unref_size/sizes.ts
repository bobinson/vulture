import fs from "node:fs";

export function positiveTtl(ms: number): boolean {
  return ms > 0;
}

export function sizeOf(filePath: string): number | undefined {
  try {
    return fs.statSync(filePath).size; // EXPECT: clean check=cwe.input_validation.path_traversal
  } catch {
    return undefined;
  }
}
