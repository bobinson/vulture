function wipe(req, store) {
  store.exec("DELETE FROM t WHERE id = " + Number(req.query.id)); // EXPECT: clean
}
module.exports = { wipe };
