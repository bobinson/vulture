function strip(p, x) {
  p = p.replace(/^\/*/, "");
  eval(x); // EXPECT: finding
  return p;
}
