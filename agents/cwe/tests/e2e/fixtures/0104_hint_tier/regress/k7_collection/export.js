const fs = require("fs");
const path = require("path");
const app = require("express")();
app.post("/export", (req, res) => {
  const allowed = req.body.folders;
  const folder = allowed.includes(req.query.folder) ? req.query.folder : "default";
  fs.readdir(path.join("/srv/exports", folder), (e, files) => res.json(files)); // EXPECT: finding check=cwe.input_validation.path_traversal
});
