// pins: a cookies member of a request-rooted chain stays a request source - req.cookies.theme reaching res.sendFile in a registered handler reports (positive)
const express = require("express");
const path = require("path");

const app = express();

app.get("/theme", (req, res) => {
  const theme = req.cookies.theme;
  res.sendFile(path.join(__dirname, "themes", theme));
});
