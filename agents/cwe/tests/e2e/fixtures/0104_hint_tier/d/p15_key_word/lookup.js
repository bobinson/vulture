const fs = require("fs");
const app = require("express")();
app.get("/a", (req, res) => {
  fs.readFile(shelf.pathForHash(req.query.h), () => {}); // EXPECT: finding check=cwe.input_validation.path_traversal
});
