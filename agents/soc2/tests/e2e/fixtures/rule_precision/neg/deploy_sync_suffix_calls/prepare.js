const fs = require("fs");

function prepare(dir) {
  fs.mkdirSync(dir, { recursive: true });
  return fs.readdirSync(dir, { withFileTypes: true });
}

module.exports = { prepare };
