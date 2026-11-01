// pins: argv is the operator's own argument - a command-line program's process.argv[2] reaching fs.readFileSync is unknown(argv), no external source (negative)
const fs = require("fs");

const reportPath = process.argv[2];
const report = fs.readFileSync(reportPath, "utf8");
console.log(report.split("\n").length);
