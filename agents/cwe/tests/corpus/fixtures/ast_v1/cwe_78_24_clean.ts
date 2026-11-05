// pins: a multi-word helper name is no command sink - executeTallyAction(...) only starts with an exec word; it carries no process concept, so req.body.choice reaching it runs no command (negative)
import express from "express";
import { executeTallyAction } from "./ballots";

const app = express();

app.post("/vote", async (req, res) => {
  const outcome = await executeTallyAction(req.body.choice);
  res.json(outcome);
});
