try { f() } catch (e) {
  // EXPECT-NEXT: finding  js String e
  res.send(String(e))
}
