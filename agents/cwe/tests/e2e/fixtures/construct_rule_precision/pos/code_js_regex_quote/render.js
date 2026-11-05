function render(s, code) {
  s = s.replace(/"/g, "&quot;"); eval(code); // EXPECT: finding
  return s;
}
