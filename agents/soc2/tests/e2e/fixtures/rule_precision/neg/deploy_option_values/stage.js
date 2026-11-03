const { execFileSync } = require("child_process");

function stage(root) {
  execFileSync("rsync", ["-a", "dist/", "out/"], { cwd: root, stdio: "inherit" });
}

module.exports = { stage };
