// pins: a data store is no process - db.exec(...) on a database handle runs SQL (CWE-89's concern), not an OS command, though the statement is built from req.body.owner (negative)
const express = require("express");
const { openDatabase } = require("./storage");

const app = express();
const db = openDatabase("drafts.sqlite");

app.post("/drafts/purge", (req, res) => {
  db.exec(`DELETE FROM drafts WHERE owner = '${req.body.owner}'`);
  res.end();
});
