import fs from "node:fs";

export function shelve(destPath: string, req: any): void {
  fs.copyFileSync(req.query.src, destPath); // EXPECT: finding check=cwe.input_validation.path_traversal SINKS=none
}

export function unshelve(destPath: string): void {
  fs.unlinkSync(destPath); // EXPECT: finding check=cwe.input_validation.path_traversal SINKS=none
}

export function reshelve(destPath: string, label: string): void {
  fs.appendFileSync(destPath, label); // EXPECT: finding check=cwe.input_validation.path_traversal SINKS=none
}
