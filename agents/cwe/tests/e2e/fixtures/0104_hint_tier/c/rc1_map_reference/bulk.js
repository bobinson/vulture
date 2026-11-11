const express = require("express");
const fs = require("fs");

const app = express();
app.use(express.json());

function pathPresent(filePath) {
  return fs.existsSync(filePath); // EXPECT: finding check=cwe.input_validation.path_traversal
}

app.post("/bulk-exists", (req, res) => {
  res.json(req.body.paths.map(pathPresent));
});

module.exports = app;
