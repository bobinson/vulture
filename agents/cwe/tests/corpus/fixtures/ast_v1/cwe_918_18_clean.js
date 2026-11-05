// pins: a Map construction is no HTTP client - previewCache is bound to new Map(), so previewCache.get(req.query.url) reads an in-memory entry even though its key is URL-shaped (negative)
const express = require("express");

const app = express();
const previewCache = new Map();

app.get("/preview", (req, res) => {
  const entry = previewCache.get(req.query.url);
  res.json(entry || {});
});
