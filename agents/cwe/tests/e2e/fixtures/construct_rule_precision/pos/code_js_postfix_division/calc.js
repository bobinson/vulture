function f(i, n, s) {
  var r = i++ / 2; eval(s); var q = n / 3; // EXPECT: finding
  return r + q;
}
