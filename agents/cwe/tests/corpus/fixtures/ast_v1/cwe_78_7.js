// pins: shell-via-flag argv array, the element after a -c flag literal behind a shell interpreter carries a request field (positive)
const cp = require("child_process");

function handler(req, res) {
  const cmd = req.query.cmd;
  cp.spawn("sh", ["-c", cmd]);
}
