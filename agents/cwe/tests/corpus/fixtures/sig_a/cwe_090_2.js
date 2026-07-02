// CWE-90: LDAP filter built by concatenating untrusted request input.
function findUser(client, req) {
  const uid = req.query.uid;
  const opts = { filter: "(uid=" + uid + ")", scope: "sub" };
  return client.search("ou=people,dc=example,dc=com", opts);
}

module.exports = { findUser };
