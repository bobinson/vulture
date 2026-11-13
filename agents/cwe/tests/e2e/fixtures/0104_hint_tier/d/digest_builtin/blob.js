const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
exports.get = function (req, res) {
  const key = crypto.hash("sha256", req.query.name);
  res.send(fs.readFileSync(path.join("/srv/blobs", key))); // EXPECT: clean check=cwe.input_validation.path_traversal
};
