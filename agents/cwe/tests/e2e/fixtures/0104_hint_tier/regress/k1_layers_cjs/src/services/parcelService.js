const { readParcel } = require("../storage/parcels");

function getParcel(orderId, name) {
  note(orderId, name);
  return readParcel(name);
}

function note(orderId, name) {
  console.log("parcel", orderId, name);
}

module.exports = { getParcel };
