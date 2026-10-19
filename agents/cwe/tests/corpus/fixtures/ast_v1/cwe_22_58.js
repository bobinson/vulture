// pins: params stays a request source as a member of a request-rooted chain - const { name } = req.params in a registered route handler reaches fs.readFile (positive)
const express = require("express");
const fs = require("fs");
const path = require("path");

const router = express.Router();

router.get("/notes/:name", (req, res) => {
  const { name } = req.params;
  fs.readFile(path.join("notes", name), (err, data) => res.send(data));
});
