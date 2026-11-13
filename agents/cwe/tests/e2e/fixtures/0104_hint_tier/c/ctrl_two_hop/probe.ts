import express from "express";
import { accessSync, constants } from "fs";

export function writable(filePath: string): boolean {
  try {
    accessSync(filePath, constants.W_OK); // EXPECT: finding check=cwe.input_validation.path_traversal
    return true;
  } catch {
    return false;
  }
}

function relay(p: string) {
  return writable(p);
}

export const app = express();
app.get("/w", (req, res) => res.json({ ok: relay(String(req.query.p)) }));
