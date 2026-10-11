try { f() } catch (x) {
  // EXPECT-NEXT: finding  js non-error-named catch binding
  res.json({ m: x.message })
}
