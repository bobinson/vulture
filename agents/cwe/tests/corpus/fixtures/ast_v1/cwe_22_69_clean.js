// pins: cookie is a container word - a helper's cookieName parameter names no request outside handler context, so it reaching fs.unlink is unknown(param) (negative)
const fs = require("fs");

function dropCachedCookie(cookieName) {
  fs.unlink(`/var/cache/jar/${cookieName}.json`, () => {});
}

module.exports = { dropCachedCookie };
