// pins: a generic container parameter outside handler context is no request source - pushDigest(label, params) is an exported helper, so params.endpoint reaching apiClient.post is unknown(param), not external(request) (negative)
const { apiClient } = require("./clients");

async function pushDigest(label, params) {
  const endpoint = params.endpoint;
  await apiClient.post(endpoint, { label, items: params.items });
}

module.exports = { pushDigest };
