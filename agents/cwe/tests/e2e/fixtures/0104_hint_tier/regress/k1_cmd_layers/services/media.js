const { makePreview } = require("../lib/previews");

function processCrate(record) {
  makePreview(record.storedAs);
  return { preview: `previews/${record.storedAs}` };
}

module.exports = { processCrate };
