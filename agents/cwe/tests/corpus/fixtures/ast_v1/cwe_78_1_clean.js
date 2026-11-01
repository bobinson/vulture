// pins: argv-array form, the request body field is an array element after a constant program name with no shell (clean)
const cp = require("child_process");

function handler(req, res) {
  const name = req.body.name;
  cp.spawn("ls", [name]);
}
