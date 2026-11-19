function run(h, req) {
  h.exec("psql -c 'DELETE FROM t WHERE id = " + req.query.id + "'"); // EXPECT: finding
}
module.exports = { run };
