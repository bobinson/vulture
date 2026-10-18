// pins: a flag literal with no shell interpreter as the program - cp.spawn("ping", ["-c", "1", req.query.host]) runs no shell, so the request field is an argument, not a command (argument injection is CWE-88, not CWE-78) (negative)
const cp = require("child_process");

function handler(req, res) {
  cp.spawn("ping", ["-c", "1", req.query.host]);
  res.end();
}
