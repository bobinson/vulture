const Database = require("better-sqlite3");
function wipe(req, res) {
  const store = new Database("app.db");
  store.exec(`DELETE FROM t WHERE id = ${req.body.id}`); // EXPECT: finding
}
