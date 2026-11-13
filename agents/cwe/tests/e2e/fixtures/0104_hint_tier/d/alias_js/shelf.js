const fs = require("fs");
const path = require("path");
const hash = path.join;
exports.get = function (req, res) {
  res.send(fs.readFileSync(hash("/srv/shelf", req.query.name))); // EXPECT: finding check=cwe.input_validation.path_traversal
};
