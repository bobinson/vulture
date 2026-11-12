const fs = require("fs");
const path = require("path");
const layout = { hash: path.join };
exports.get = function (req, res) {
  res.send(fs.readFileSync(layout.hash("/srv/shelf", req.query.name))); // EXPECT: finding check=cwe.input_validation.path_traversal
};
