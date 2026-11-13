const fs = require("fs");
const path = require("path");

function keepFile({ fileName, data }) {
  fs.appendFileSync(path.join("/srv/store", fileName), data); // EXPECT: finding check=cwe.input_validation.path_traversal
}

module.exports = { keepFile };
