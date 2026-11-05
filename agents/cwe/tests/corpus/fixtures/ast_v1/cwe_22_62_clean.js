// pins: a same-file helper that tests its parameter with a containment guard and exits early guards its caller's argument - screenEntry(entry) throws unless the resolved entry stays under BASE_DIR (negative)
const express = require("express");
const fs = require("fs");
const path = require("path");

const BASE_DIR = "/srv/library";
const app = express();

function screenEntry(entry) {
  if (!path.resolve(BASE_DIR, entry).startsWith(BASE_DIR + path.sep)) {
    throw new Error("outside the library");
  }
}

app.get("/book", (req, res) => {
  const entry = req.query.entry;
  screenEntry(entry);
  fs.readFile(path.join(BASE_DIR, entry), (err, data) => res.send(data));
});
