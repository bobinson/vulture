function firstWord(req) {
  return /^(\w+)/.exec("SELECT a FROM t WHERE b = " + req.query.q); // EXPECT: clean
}
module.exports = { firstWord };
