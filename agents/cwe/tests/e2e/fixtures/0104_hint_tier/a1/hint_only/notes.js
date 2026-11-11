const fs = require("fs");

function loadNote(filePath, req) {
  return fs.readFileSync(filePath + ".txt"); // EXPECT: finding check=cwe.input_validation.path_traversal HINT=param_hint
}

module.exports = { loadNote };
