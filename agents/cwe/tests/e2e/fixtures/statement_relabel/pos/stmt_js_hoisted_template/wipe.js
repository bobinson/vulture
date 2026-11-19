function wipe(req, store) {
  const q = `DELETE FROM t WHERE id = ${req.body.id}`; // EXPECT: finding
  store.exec(q);
}
module.exports = { wipe };
