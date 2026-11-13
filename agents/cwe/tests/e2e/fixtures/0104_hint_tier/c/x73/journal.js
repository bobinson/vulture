const fs = require("node:fs");
const path = require("node:path");

const JOURNAL_ROOT = "/srv/journal";

function checkAndNote(filePath, req) {
  fs.access(filePath, fs.constants.R_OK, (err) => { // EXPECT: clean check=cwe.input_validation.path_traversal
    noteAccess(path.join(JOURNAL_ROOT, req.query.user), err); // EXPECT: finding check=cwe.input_validation.external_path_control
  });
}

module.exports = { checkAndNote };
