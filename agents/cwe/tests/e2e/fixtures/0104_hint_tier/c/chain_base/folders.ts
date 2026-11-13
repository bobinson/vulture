import fs from "node:fs";
import path from "node:path";

const VAULT_ROOT = "/srv/vault";

export function folderExists(fileName: string): boolean {
  const parsed = path.parse(path.join(VAULT_ROOT, fileName));
  return fs.existsSync(parsed.dir); // EXPECT: finding check=cwe.input_validation.path_traversal
}
