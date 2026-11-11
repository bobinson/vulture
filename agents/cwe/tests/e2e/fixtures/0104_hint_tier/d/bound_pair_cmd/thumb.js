const { exec } = require("child_process");
const express = require("express");
const app = express();
const names = {
  hash: (f) => f.replace(/\s+/g, "_"),
};
app.get("/thumb", (req, res) => {
  exec("convert " + names.hash(req.query.f) + " thumb.png", () => res.end()); // EXPECT: finding check=cwe.injection.command
});
module.exports = app;
