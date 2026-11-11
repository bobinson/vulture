// pins: 0104 WS-C - bare existsSync / accessSync / lstatSync probes of exported functions' hinted parameters, listed in module.exports (negative)
const fs = require("node:fs");

function present(filePath) {
  return fs.existsSync(filePath);
}

function readable(fileName) {
  fs.accessSync(fileName, fs.constants.R_OK);
  return true;
}

function folder(filePath) {
  return fs.lstatSync(filePath).isDirectory();
}

module.exports = { present, readable, folder };
