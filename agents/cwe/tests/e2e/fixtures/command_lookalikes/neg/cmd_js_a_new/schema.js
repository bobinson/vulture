const Database = require("better-sqlite3");
function mk(name) {
  const store = new Database("x.db");
  store.exec("CREATE TABLE " + name + " (id)"); // EXPECT: clean
}
module.exports = { mk };
