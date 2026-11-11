const { exec } = require("child_process");
const express = require("express");
const app = express();
const ALIASES = new Map([["status", "git status"], ["log", "git log -n 5"]]);
app.get("/run", (req, res) => {
  const name = req.query.cmd;
  const command = ALIASES.has(name) ? ALIASES.get(name) : name;
  exec(command, (err, out) => res.send(out)); // EXPECT: finding check=cwe.injection.command
});
