function show(a, y) {
  return `${a ? `x` : eval(y)}`; // EXPECT: finding
}
