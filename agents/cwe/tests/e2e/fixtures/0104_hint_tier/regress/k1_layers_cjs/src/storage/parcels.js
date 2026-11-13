const fs = require("fs");
const path = require("path");

const PARCEL_DIR = path.join(__dirname, "..", "..", "store", "parcels");

function readParcel(fileName) {
  return fs.readFileSync(path.join(PARCEL_DIR, fileName)); // EXPECT: finding check=cwe.input_validation.path_traversal
}

module.exports = { readParcel };
