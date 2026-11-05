function f(x) {
  const y = x; /* eval(x) is not used */ return y; // EXPECT: clean
}
