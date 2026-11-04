function run(x) {
  const note = "call eval(x) only in tests"; // EXPECT: clean
  return x; // never eval(x) here   EXPECT: clean
}
