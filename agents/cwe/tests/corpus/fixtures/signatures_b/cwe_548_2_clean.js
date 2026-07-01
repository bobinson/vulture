// Safe: autoIndex explicitly disabled.
const server = http.createServer({ autoIndex: false, root: "/srv/public" });
