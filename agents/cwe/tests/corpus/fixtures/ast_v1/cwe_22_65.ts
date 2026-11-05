// pins: a synchronous file API is a path sink like its asynchronous stem - fs.unlinkSync(...) of a request-chosen cache entry (positive)
import express from "express";
import fs from "node:fs";
import path from "node:path";

const CACHE_ROOT = "/var/cache/app";
const app = express();

app.delete("/cache/:entry", (req, res) => {
  fs.unlinkSync(path.join(CACHE_ROOT, req.params.entry));
  res.end();
});
