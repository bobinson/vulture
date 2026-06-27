// CWE-548: autoIndex turned on for static directory.
const server = http.createServer({ autoIndex: true, root: "/srv/public" });
