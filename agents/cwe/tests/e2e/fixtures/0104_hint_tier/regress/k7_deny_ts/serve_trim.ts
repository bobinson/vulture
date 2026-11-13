import { readFile } from "fs/promises";
import path from "path";
import express from "express";
const app = express();
const DENIED = [".env", "package.json"];
app.get("/static", async (req, res) => {
  const asked = String(req.query.f);
  const f = DENIED.includes(asked) ? "index.html" : asked.trim();
  res.send(await readFile(path.join(__dirname, "public", f))); // EXPECT: finding check=cwe.input_validation.path_traversal
});
