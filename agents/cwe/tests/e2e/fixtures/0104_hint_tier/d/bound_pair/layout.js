const fs = require("fs");
const path = require("path");
const ROOT = "/srv/shards";
const layout = {
  hash: (name) => name.slice(0, 2) + "/" + name,
};
exports.get = function (req, res) {
  res.send(fs.readFileSync(path.join(ROOT, layout.hash(req.query.name)))); // EXPECT: finding check=cwe.input_validation.path_traversal
};
