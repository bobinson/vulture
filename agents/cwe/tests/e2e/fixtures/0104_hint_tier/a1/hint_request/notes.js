const fs = require("fs");

function loadNote(filePath, req) {
  return fs.readFileSync(filePath + req.query.ext); // EXPECT: finding check=cwe.input_validation.path_traversal HINT=none
}

module.exports = { loadNote };
