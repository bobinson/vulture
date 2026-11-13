const fs = require("fs");
const app = require("express")();
app.post("/a", (req, res) => {
  const file = require("lodash").get(req.body, "file");
  fs.readFile(file, (e, d) => res.send(d)); // EXPECT: finding check=cwe.input_validation.path_traversal
});
