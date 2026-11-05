// pins: a Set construction is no HTTP client - liveSessions is bound to new Set(), so liveSessions.delete(req.body.sessionId) removes an in-memory member, not a request (negative)
const express = require("express");

const app = express();
const liveSessions = new Set();

app.post("/logout", (req, res) => {
  liveSessions.delete(req.body.sessionId);
  res.end();
});
