import fs from "node:fs";

export function fileInfo(filePath: string) {
  return fs.statSync(filePath); // EXPECT: finding check=cwe.input_validation.path_traversal
}

export function register(app: any): void {
  app.get("/info", (req: any, res: any) => {
    res.json(fileInfo(String(req.query.path)));
  });
}
