const express = require("express");
const fsp = require("fs/promises");

const app = express();

function statOf(filePath) {
  return fsp.stat(filePath); // EXPECT: finding check=cwe.input_validation.path_traversal
}

app.get("/meta", (req, res) => {
  Promise.resolve(req.query.p)
    .then(statOf)
    .then((st) => res.json({ size: st.size }));
});

module.exports = app;
