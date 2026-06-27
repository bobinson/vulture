// nginx-style static config object passed to a custom server.
// Safe: directory auto-indexing explicitly disabled.
const config = {
  root: "/srv/uploads",
  autoIndex: false,
};
