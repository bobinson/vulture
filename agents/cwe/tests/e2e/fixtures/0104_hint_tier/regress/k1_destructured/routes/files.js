const { keepFile } = require("../lib/store");

module.exports = function register(app) {
  app.post("/files", (req, res) => {
    keepFile({ fileName: req.body.name, data: req.body.data });
    res.sendStatus(201);
  });
};
