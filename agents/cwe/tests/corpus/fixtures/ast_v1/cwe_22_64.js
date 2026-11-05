// pins: a synchronous two-path file API is a path sink like its asynchronous stem - fs.renameSync(staged, ...) moves a staged file to a request-chosen name (positive)
const express = require("express");
const fs = require("fs");
const path = require("path");

const ARCHIVE_ROOT = "/srv/archive";
const app = express();

app.post("/archive", (req, res) => {
  const staged = path.join(ARCHIVE_ROOT, "staged.bin");
  fs.renameSync(staged, path.join(ARCHIVE_ROOT, req.body.name));
  res.end();
});
