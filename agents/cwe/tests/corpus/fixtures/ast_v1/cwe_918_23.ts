// pins: a generic verb on a plain receiver stays a request sink when its argument is URL-shaped - relay.post(callbackUrl, ...) with callbackUrl bound to req.body.callback (positive)
import express from "express";
import { relay } from "./outbound";

const app = express();

app.post("/notify", async (req, res) => {
  const callbackUrl = req.body.callback;
  await relay.post(callbackUrl, { status: "done" });
  res.end();
});
