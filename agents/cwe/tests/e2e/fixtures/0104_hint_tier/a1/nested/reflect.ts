import fs from "node:fs";

export function reflect(sourcePath: string, filePath: string, req: any): void {
  fs.appendFileSync(req.query.dest, fs.readFileSync(filePath)); // EXPECT: finding check=cwe.input_validation.path_traversal HINT=none SHOWS=request
}
