const path = require("path");
const { makePreview } = require("../lib/previews");

module.exports = function register(app) {
  app.post("/previews", (req, res) => {
    makePreview(path.basename(req.body.name));
    res.sendStatus(202);
  });
};
