// nginx-style static config object passed to a custom server.
// CWE-548: autoIndex turned on exposes the full directory tree.
const config = {
  root: "/srv/uploads",
  autoIndex: true,
};
