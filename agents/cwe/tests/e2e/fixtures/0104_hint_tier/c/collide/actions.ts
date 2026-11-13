"use server";

import fs from "node:fs";
import path from "node:path";

const CRATE_ROOT = "/srv/app/crates";

export function crateFound(filePath: string): boolean {
  return fs.existsSync(filePath); // EXPECT: finding check=cwe.input_validation.path_traversal
}

export async function crateExists(fileName: string) {
  return crateFound(path.join(CRATE_ROOT, fileName));
}
