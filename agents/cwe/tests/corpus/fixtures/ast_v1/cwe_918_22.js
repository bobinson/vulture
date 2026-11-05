// pins: an HTTP client verb stays a request sink - upstreamClient.get(target) on a client-concept receiver, target bound to req.query.target (positive)
const express = require("express");
const { upstreamClient } = require("./clients");

const app = express();

app.get("/relay", async (req, res) => {
  const target = req.query.target;
  const reply = await upstreamClient.get(target);
  res.send(reply.data);
});
