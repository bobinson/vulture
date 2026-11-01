// pins: a synchronous file API is a path sink like its asynchronous stem - fs.mkdirSync(...) of a request-chosen folder under UPLOAD_ROOT (positive)
const express = require("express");
const fs = require("fs");
const path = require("path");

const UPLOAD_ROOT = "/srv/uploads";
const app = express();

app.post("/folders", (req, res) => {
  fs.mkdirSync(path.join(UPLOAD_ROOT, req.body.folder), { recursive: true });
  res.end();
});
