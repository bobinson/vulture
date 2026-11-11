const fs = require("fs");

function readFirst(fileName, cb) {
  // EXPECT-NEXT: clean check=cwe.input_validation.path_traversal
  fs.readFile(fileName + "/..%2fone.txt", cb); // EXPECT: finding check=cwe.path_eq.cwe_23
}

function readSecond(fileName, cb) {
  fs.readFile(fileName, cb); // EXPECT: finding check=cwe.input_validation.path_traversal SINKS=none
}

function readThird(filePath, cb) {
  fs.readFile(filePath, cb); // EXPECT: finding check=cwe.input_validation.path_traversal SINKS=none
}

module.exports = { readFirst, readSecond, readThird };
