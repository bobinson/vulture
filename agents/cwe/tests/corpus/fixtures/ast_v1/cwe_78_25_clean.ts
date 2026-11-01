// pins: a multi-word UI name is no command sink - new ExecReviewPanel(...) builds a view object whose name starts with an exec word; req.body.note reaching it runs no command (negative)
import express from "express";
import { ExecReviewPanel } from "./panels";

const app = express();

app.post("/review", (req, res) => {
  const panel = new ExecReviewPanel(req.body.note);
  res.send(panel.render());
});
