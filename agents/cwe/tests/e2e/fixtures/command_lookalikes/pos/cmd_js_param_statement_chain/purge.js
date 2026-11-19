function run(h, req) {
  h.exec("DELETE FROM t; " + req.query.c); // EXPECT: finding
}
module.exports = { run };
