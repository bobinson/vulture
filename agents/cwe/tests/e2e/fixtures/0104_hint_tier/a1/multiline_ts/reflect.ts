import fs from "node:fs";

export function reflect(filePath: string, req: any): void {
  fs.appendFileSync( // EXPECT: finding check=cwe.input_validation.path_traversal HINT=none SHOWS=request
    req.query.dest,
    fs.readFileSync(filePath) // EXPECT: finding check=cwe.input_validation.path_traversal HINT=param_hint
  );
}
