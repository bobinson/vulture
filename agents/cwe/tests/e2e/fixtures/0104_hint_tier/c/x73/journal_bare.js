const fs = require("node:fs");

function checkOnly(filePath) {
  fs.access(filePath, fs.constants.R_OK, (err) => { // EXPECT: clean check=cwe.input_validation.path_traversal
    noteAccess(filePath, err);
  });
}

module.exports = { checkOnly };
