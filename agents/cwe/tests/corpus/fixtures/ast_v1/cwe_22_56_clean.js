// pins: a generic container parameter outside handler context is no request source - writeSnapshot(params) is an exported helper, so params.stateDir reaching fs.writeFile is unknown(param), not external(request) (negative)
const fs = require("fs");
const path = require("path");

function writeSnapshot(params) {
  const target = path.join(params.stateDir, "snapshot.json");
  fs.writeFile(target, JSON.stringify(params.entries), () => {});
}

module.exports = { writeSnapshot };
