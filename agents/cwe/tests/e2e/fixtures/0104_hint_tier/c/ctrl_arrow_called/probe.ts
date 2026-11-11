import express from "express";
import { existsSync } from "fs";

export const present = (filePath: string) => existsSync(filePath); // EXPECT: finding check=cwe.input_validation.path_traversal

export const app = express();
app.get("/exists", (req, res) => {
  res.json({ ok: present(String(req.query.p)) });
});
