// pins: a generic collection verb with no HTTP-client evidence - store.grants.put/get on a receiver chain naming no client or transport concept, keyed by a request token that is not URL-shaped (negative)
import express from "express";
import { store } from "./state";

const app = express();

app.post("/grant", (req, res) => {
  const token = req.cookies.token;
  store.grants.put(token, { granted: Date.now() });
  res.json(store.grants.get(token));
});
