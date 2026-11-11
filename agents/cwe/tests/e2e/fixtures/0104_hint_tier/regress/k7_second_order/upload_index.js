const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const express = require("express");
const app = express();
const pending = new Map();
app.post("/upload/start", express.json(), (req, res) => {
  const id = crypto.randomUUID();
  pending.set(id, req.body.filename);
  res.json({ id });
});
app.post("/upload/:id", (req, res) => {
  const filename = pending[req.params.id];
  req.pipe(fs.createWriteStream(path.join("/srv/crates", filename))); // EXPECT: finding check=cwe.input_validation.path_traversal
});
