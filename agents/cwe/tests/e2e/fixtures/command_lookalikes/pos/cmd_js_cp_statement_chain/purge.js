const cp = require("child_process");
function f(x) { cp.exec("DELETE FROM t; " + x); } // EXPECT: finding
