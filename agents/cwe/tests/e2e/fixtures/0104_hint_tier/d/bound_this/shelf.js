const fs = require("fs");
const path = require("path");
function Shelf(root) {
  this.hash = (name) => path.join(root, name);
}
const shelf = new Shelf("/srv/shards");
exports.get = function (req, res) {
  res.send(fs.readFileSync(shelf.hash(req.query.name))); // EXPECT: finding check=cwe.input_validation.path_traversal
};
