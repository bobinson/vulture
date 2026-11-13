const express = require("express");
const fs = require("fs");

const app = express();

function existsHandler({ query: { filePath } }, res) {
  res.json({ exists: fs.existsSync(filePath) }); // EXPECT: finding check=cwe.input_validation.path_traversal
}

app.get("/exists", existsHandler);
module.exports = app;
