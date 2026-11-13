const media = require("../services/media");

module.exports = function register(app) {
  app.post("/media", (req, res) => {
    res.json(media.processCrate({ storedAs: req.body.name }));
  });
};
