import { promises as fs } from "node:fs";
import path from "node:path";

const WORKBENCH = "/srv/workbench";

export async function dropBenchFile(fileName: string): Promise<void> {
  await fs.unlink(path.join(WORKBENCH, fileName)); // EXPECT: finding check=cwe.input_validation.path_traversal
}
