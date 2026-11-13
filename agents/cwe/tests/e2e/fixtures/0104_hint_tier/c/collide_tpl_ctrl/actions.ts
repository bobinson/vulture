"use server";

import fs from "node:fs";

const CRATE_ROOT = "/srv/app/crates";

export async function crateExists(fileName: string) {
  return fs.existsSync(`${CRATE_ROOT}/${fileName}`); // EXPECT: finding check=cwe.input_validation.path_traversal
}
