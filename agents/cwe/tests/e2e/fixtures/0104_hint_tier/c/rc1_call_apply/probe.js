const express = require("express");
const fs = require("fs");

const app = express();

function checkPath(filePath) {
  return fs.existsSync(filePath); // EXPECT: finding check=cwe.input_validation.path_traversal
}

app.get("/a", (req, res) => res.json(checkPath.call(null, req.query.p)));
app.get("/b", (req, res) => res.json(checkPath.apply(null, [req.query.p])));

module.exports = app;
