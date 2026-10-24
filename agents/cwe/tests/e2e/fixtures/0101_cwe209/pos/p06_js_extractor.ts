try { f() } catch (e) {
  // EXPECT-NEXT: finding  js extractor
  res.json({ m: getErrorMessage(e) })
}
