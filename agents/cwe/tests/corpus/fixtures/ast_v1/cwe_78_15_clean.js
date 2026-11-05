// pins: env as a command source, an operator-set variable interpolated into a template that is arg 0 of a strong command sink (clean)
const cp = require("child_process");

function main() {
  cp.exec(`ls ${process.env.DIR}`);
}

main();
