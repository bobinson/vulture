try { f() } catch (err) {
  // EXPECT-NEXT: clean  endsWith not a sink
  if (name.endsWith(err.message)) return
}
