// pins: argv as a command source, a process argument interpolated into a template that is arg 0 of a strong command sink (positive)
const cp = require("child_process");

function main() {
  cp.exec(`ls ${process.argv[2]}`);
}

main();
