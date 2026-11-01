// pins: membership guard with early return, the request field must be in a constant array before a strong command sink (clean)
const cp = require("child_process");

function handler(req, res) {
  const cmd = req.query.cmd;
  if (!["ls", "df"].includes(cmd)) return;
  cp.exec(cmd);
}
