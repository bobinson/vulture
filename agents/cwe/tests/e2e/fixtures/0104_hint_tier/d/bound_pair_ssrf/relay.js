const express = require("express");
const app = express();
const route = {
  hash: (u) => u.trim(),
};
app.get("/fetch", async (req, res) => {
  const r = await fetch(route.hash(req.query.u)); // EXPECT: finding check=cwe.injection.ssrf
  res.send(await r.text());
});
module.exports = app;
