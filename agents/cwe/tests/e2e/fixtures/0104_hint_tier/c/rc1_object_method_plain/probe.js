const express = require("express");
const fs = require("fs");

const checker = {
  present(filePath) {
    return fs.existsSync(filePath); // EXPECT: finding check=cwe.input_validation.path_traversal
  },
};

const app = express();
app.get("/exists", (req, res) => {
  res.json({ ok: checker.present(req.query.p) });
});

module.exports = { checker, app };
