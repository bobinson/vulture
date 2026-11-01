// pins: a same-file function named like a strong command sink shadows it, so its call is not a sink (clean)
function exec(cmd) {
  return cmd.length;
}

function handler(req, res) {
  const name = req.body.name;
  exec(`ls ${name}`);
}
