// pins: a synchronous file API is a path sink like its asynchronous stem - fs.rmSync(...) of a request-chosen workspace under WORK_ROOT (positive)
const express = require("express");
const fs = require("fs");
const path = require("path");

const WORK_ROOT = "/srv/workspaces";
const app = express();

app.post("/workspaces/drop", (req, res) => {
  fs.rmSync(path.join(WORK_ROOT, req.body.workspace), { recursive: true, force: true });
  res.end();
});
