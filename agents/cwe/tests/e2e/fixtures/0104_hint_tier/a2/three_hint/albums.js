const fs = require("fs");

function readAlbum(filePath) {
  return fs.readFileSync(filePath, "utf8"); // EXPECT: finding check=cwe.input_validation.path_traversal SINKS=4_8_12
}

function tagAlbum(filePath, label) {
  fs.appendFileSync(filePath, label); // EXPECT: clean check=cwe.input_validation.path_traversal
}

function dropAlbum(fileName) {
  fs.unlinkSync(fileName); // EXPECT: clean check=cwe.input_validation.path_traversal
}

module.exports = { readAlbum, tagAlbum, dropAlbum };
