const fs = require("fs");
const { get } = require("axios");
const express = require("express");

const app = express();

app.get("/f", (req, res) => {
  res.send(fs.readFileSync(req.query.p)); // EXPECT: finding check=cwe.input_validation.path_traversal
});

app.get("/u", async (req, res) => {
  await fetch(req.query.u); // EXPECT: finding check=cwe.injection.ssrf
  await get(req.query.u); // EXPECT: finding check=cwe.injection.ssrf
  res.send("ok");
});
