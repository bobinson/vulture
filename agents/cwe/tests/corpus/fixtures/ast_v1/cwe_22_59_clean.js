// pins: a statement-level validation call guards the path role - assertInsideRoot(target, DOC_ROOT) runs before fs.readFile(target) in the same block and takes the flow's variable (negative)
const express = require("express");
const fs = require("fs");
const path = require("path");
const { assertInsideRoot } = require("./guards");

const DOC_ROOT = "/srv/docs";
const app = express();

app.get("/doc", (req, res) => {
  const target = path.join(DOC_ROOT, req.query.name);
  assertInsideRoot(target, DOC_ROOT);
  fs.readFile(target, (err, data) => res.send(data));
});
