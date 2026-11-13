import fs from "node:fs";

export function shelve(destPath: string, req: any): void {
  fs.copyFileSync(req.query.src, destPath); // EXPECT: finding check=cwe.input_validation.path_traversal HINT=none SHOWS=request
}
