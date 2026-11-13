const fs = require("fs");
const express = require("express");
const app = express();

app.get("/sheet", (req, res) => {
  res.send(fs.readFileSync(req.query.name, "utf8")); // EXPECT: finding check=cwe.input_validation.path_traversal SINKS=none
});

function loadSheet(fileName) {
  return fs.readFileSync(fileName, "utf8"); // EXPECT: finding check=cwe.input_validation.path_traversal SINKS=none
}

function tagSheet(filePath, label) {
  fs.appendFileSync(filePath, label); // EXPECT: finding check=cwe.input_validation.path_traversal SINKS=none
}

module.exports = { app, loadSheet, tagSheet };
