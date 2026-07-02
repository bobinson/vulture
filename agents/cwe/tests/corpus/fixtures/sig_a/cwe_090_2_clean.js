// Safe: reject any uid that is not a bare alphanumeric token, then bind it
// through the driver's escaping API rather than concatenating into a filter.
const { escapeFilter } = require("ldapjs");

function findUser(client, req) {
  const uid = req.query.uid;
  if (!/^[a-zA-Z0-9]{1,32}$/.test(uid)) {
    throw new Error("invalid uid");
  }
  const safe = escapeFilter(uid);
  return client.search("ou=people,dc=example,dc=com", { filter: safe, scope: "sub" });
}

module.exports = { findUser };
