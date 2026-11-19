const cp = require("child_process");
function f(x) { cp.exec("psql -c 'DELETE FROM t WHERE id = " + x + "'"); } // EXPECT: finding
