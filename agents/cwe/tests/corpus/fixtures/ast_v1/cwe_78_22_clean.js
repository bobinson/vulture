// pins: a regex is no process - the receiver of .exec(...) is a regex literal itself, so /^v(\d+)$/.exec(req.headers["x-api-version"]) matches text, it runs no command (negative)
const express = require("express");

const app = express();

app.get("/version", (req, res) => {
  const match = /^v(\d+)$/.exec(req.headers["x-api-version"]);
  res.json({ major: match ? Number(match[1]) : 0 });
});
