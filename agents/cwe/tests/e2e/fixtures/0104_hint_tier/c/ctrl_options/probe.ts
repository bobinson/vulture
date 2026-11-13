import express from "express";
import { existsSync } from "fs";

export function present({ filePath }: { filePath: string }): boolean {
  return existsSync(filePath); // EXPECT: finding check=cwe.input_validation.path_traversal
}

export const app = express();
app.get("/exists", (req, res) => {
  res.json({ ok: present({ filePath: String(req.query.p) }) });
});
