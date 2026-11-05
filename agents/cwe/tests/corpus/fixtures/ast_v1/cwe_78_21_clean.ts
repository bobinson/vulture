// pins: a regex is no process - tagMatcher is bound to a new RegExp(...) construction, so tagMatcher.exec(req.body.text) matches text, it runs no command (negative)
import express from "express";

const app = express();
const tagMatcher = new RegExp("#(\\w+)", "g");

app.post("/tags", (req, res) => {
  const found = tagMatcher.exec(req.body.text);
  res.json({ tag: found ? found[1] : null });
});
