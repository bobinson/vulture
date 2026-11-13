const fs = require("fs");
const { execSync } = require("child_process");

function pair(filePath, req) {
  // EXPECT-NEXT: finding check=cwe.injection.command HINT=none
  return execSync("ls " + req.query.dir) + fs.readFileSync(filePath); // EXPECT: finding check=cwe.input_validation.path_traversal HINT=param_hint
}

module.exports = { pair };
