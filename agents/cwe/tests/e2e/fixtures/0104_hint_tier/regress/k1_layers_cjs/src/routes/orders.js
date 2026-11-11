const router = require("express").Router();
const service = require("../services/parcelService");

router.get("/orders/:id/parcel", (req, res) => {
  res.send(service.getParcel(req.params.id, req.query.name));
});

module.exports = router;
