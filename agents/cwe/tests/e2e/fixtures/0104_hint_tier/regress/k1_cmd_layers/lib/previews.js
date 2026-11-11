const { execSync } = require("child_process");

function makePreview(fileName) {
  execSync("convert crates/" + fileName + " -resize 64x64 previews/" + fileName); // EXPECT: finding check=cwe.injection.command
}

module.exports = { makePreview };
