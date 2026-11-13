const fs = require("fs");
const path = require("path");
function Layout(root) {
  this.root = root;
}
Layout.prototype.hash = function (name) {
  return path.join(this.root, name.slice(0, 2), name);
};
const layout = new Layout("/srv/shards");
exports.get = function (req, res) {
  res.send(fs.readFileSync(layout.hash(req.query.name))); // EXPECT: finding check=cwe.input_validation.path_traversal
};
