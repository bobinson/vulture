// pins: a generic container parameter outside handler context is no request source - launchTool(params) is an exported helper, so params.program reaching cp.spawn is unknown(param), not external(request) (negative)
const cp = require("child_process");

function launchTool(params) {
  const program = params.program;
  return cp.spawn(program, ["--version"]);
}

module.exports = { launchTool };
