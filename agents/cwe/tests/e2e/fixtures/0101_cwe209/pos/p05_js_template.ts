try { f() } catch (e) {
  // EXPECT-NEXT: finding  js template
  res.send(`failed: ${e}`)
}
