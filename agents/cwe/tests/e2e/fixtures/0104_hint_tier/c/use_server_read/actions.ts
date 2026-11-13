"use server";

import fs from "node:fs";

export async function sheetText(filePath: string): Promise<string> {
  return fs.readFileSync(filePath, "utf8"); // EXPECT: finding check=cwe.input_validation.path_traversal
}
