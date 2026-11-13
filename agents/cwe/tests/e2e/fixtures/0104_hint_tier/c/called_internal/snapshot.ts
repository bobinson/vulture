import nodeFs from "node:fs";
import path from "node:path";

export function pullText(filePath: string): string | null {
  try {
    if (!nodeFs.existsSync(filePath)) { // EXPECT: clean check=cwe.input_validation.path_traversal
      return null;
    }
    const stats = nodeFs.statSync(filePath); // EXPECT: clean check=cwe.input_validation.path_traversal
    if (!stats.isFile() || stats.size <= 1) {
      return null;
    }
    return nodeFs.readFileSync(filePath, "utf-8"); // EXPECT: finding check=cwe.input_validation.path_traversal
  } catch {
    return null;
  }
}

export function restoreSnapshot(dir: string) {
  const main = pullText(path.join(dir, "snapshot.json"));
  const spare = pullText(path.join(dir, "snapshot.json.old"));
  return main ?? spare;
}
