const fs = require("fs");
const path = require("path");
function reader(hash) {
  return function read(req, res) {
    res.send(fs.readFileSync(path.join("/srv/shelf", hash(req.query.name)))); // EXPECT: clean check=cwe.input_validation.path_traversal
  };
}
module.exports = reader((n) => n.slice(0, 2) + "/" + n);
