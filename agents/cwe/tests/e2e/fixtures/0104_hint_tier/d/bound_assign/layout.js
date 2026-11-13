const fs = require("fs");
const path = require("path");
const layout = {};
Object.assign(layout, {
  hash: (name) => path.join("/srv/shards", name),
});
exports.get = function (req, res) {
  res.send(fs.readFileSync(layout.hash(req.query.name))); // EXPECT: finding check=cwe.input_validation.path_traversal
};
