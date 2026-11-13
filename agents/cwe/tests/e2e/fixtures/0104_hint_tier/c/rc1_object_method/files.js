const express = require("express");
const fs = require("fs");

const files = {
  exists(filePath) {
    return fs.existsSync(filePath); // EXPECT: finding check=cwe.input_validation.path_traversal
  },
};

const app = express();
app.get("/exists", (req, res) => {
  res.json({ ok: files.exists(req.query.p) }); // EXPECT: finding check=cwe.input_validation.path_traversal
});

module.exports = { files, app };
