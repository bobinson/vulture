import fs from "node:fs";
import path from "node:path";

const VAULT_ROOT = "/srv/vault";
const SPARE_ROOT = "/srv/spare";

export function folderPresent(fileName: string, useSpare: boolean): boolean {
  return fs.existsSync(useSpare ? path.parse(path.join(SPARE_ROOT, fileName)).dir : VAULT_ROOT); // EXPECT: finding check=cwe.input_validation.path_traversal
}
