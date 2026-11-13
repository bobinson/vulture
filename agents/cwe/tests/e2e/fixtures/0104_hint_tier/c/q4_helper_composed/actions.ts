"use server";

import { statSync } from "node:fs";
import path from "node:path";

const CRATE_ROOT = "/srv/app/crates";

function weighOf(p: string): number {
  return statSync(p).size; // EXPECT: finding check=cwe.input_validation.path_traversal
}

export async function crateWeight(filePath: string) {
  return weighOf(path.join(CRATE_ROOT, filePath));
}
