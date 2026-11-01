// pins: headers is a container word - a helper's headers parameter names no request outside handler context, so headers.origin reaching fetch is unknown(param) (negative)
const express = require("express");

async function pingOrigin(headers) {
  return fetch(headers.origin);
}

module.exports = { pingOrigin, router: express.Router() };
