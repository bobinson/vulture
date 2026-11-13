const fs = require("fs");
const express = require("express");
const app = express();

function fetchText(p) {
  return fs.readFileSync(p, "utf8"); // EXPECT: finding check=cwe.input_validation.path_traversal HINT=none SHOWS=request
}

app.get("/doc", (req, res) => {
  res.send(fetchText(req.query.name));
});

function peek(fileName) {
  return fetchText(fileName);
}

module.exports = { peek };
