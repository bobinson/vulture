const express = require("express");
const fs = require("fs");

exports.present = function (filePath) {
  return fs.existsSync(filePath); // EXPECT: finding check=cwe.input_validation.path_traversal
};

const app = express();
app.get("/exists", (req, res) => res.json(exports.present(req.query.p)));
exports.app = app;
