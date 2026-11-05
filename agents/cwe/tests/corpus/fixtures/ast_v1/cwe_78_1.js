// pins: a template-literal command interpolating a request body field is arg 0 of a strong command sink (positive)
const cp = require("child_process");

function handler(req, res) {
  const name = req.body.name;
  cp.exec(`ls ${name}`);
}
