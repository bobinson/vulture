// pins: a regex is no process - versionPattern is bound to a regex literal, so versionPattern.exec(req.query.spec) matches text, it runs no command (negative)
const express = require("express");

const app = express();
const versionPattern = /^(\w+)@(\d+)\.(\d+)$/;

app.get("/resolve", (req, res) => {
  const match = versionPattern.exec(req.query.spec);
  res.json(match ? { name: match[1] } : {});
});
