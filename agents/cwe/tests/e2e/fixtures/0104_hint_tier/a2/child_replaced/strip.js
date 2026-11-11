const fs = require("fs");

function readFirst(fileName) {
  // EXPECT-NEXT: clean check=cwe.input_validation.path_traversal
  return fs.readFileSync(fileName.replace("../", ""), "utf8"); // EXPECT: finding check=cwe.input_validation.absolute_path_traversal
}

function readSecond(fileName) {
  return fs.readFileSync(fileName, "utf8"); // EXPECT: finding check=cwe.input_validation.path_traversal SINKS=9_13
}

function readThird(filePath) {
  return fs.readFileSync(filePath, "utf8"); // EXPECT: clean check=cwe.input_validation.path_traversal
}

module.exports = { readFirst, readSecond, readThird };
