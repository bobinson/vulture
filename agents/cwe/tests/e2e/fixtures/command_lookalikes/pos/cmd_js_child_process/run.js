const cp = require("child_process");
function f(req) { cp.exec(req.query.cmd); } // EXPECT: finding
