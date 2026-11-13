const fs = require("fs");
const LABEL_RE = /^[a-z0-9_-]+$/;

function checkLabel(fileName) {
  if (!LABEL_RE.test(fileName)) {
    throw new Error("bad label");
  }
}

function loadShelf(fileName) {
  return fs.readFileSync(`/srv/shelves/${fileName}`, "utf8"); // EXPECT: finding check=cwe.input_validation.path_traversal SINKS=none STATUS=suspicious
}

function tagShelf(filePath, label) {
  fs.appendFileSync(`/srv/shelves/${filePath}`, label); // EXPECT: finding check=cwe.input_validation.path_traversal SINKS=none STATUS=suspicious
}

module.exports = { checkLabel, loadShelf, tagShelf };
