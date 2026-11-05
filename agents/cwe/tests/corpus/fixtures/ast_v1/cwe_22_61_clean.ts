// pins: a call returning a containment-checked path is a path_normalize sanitiser - safePath = resolveWithinRoot(UPLOAD_ROOT, req.query.f) replaces the request value before fs.promises.readFile (negative)
import express from "express";
import fs from "node:fs";
import { resolveWithinRoot } from "./fs-guard";

const UPLOAD_ROOT = "/srv/uploads";
const app = express();

app.get("/upload", async (req, res) => {
  const safePath = resolveWithinRoot(UPLOAD_ROOT, req.query.f);
  res.send(await fs.promises.readFile(safePath));
});
