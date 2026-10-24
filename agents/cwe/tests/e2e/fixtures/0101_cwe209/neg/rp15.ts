try { run() } catch (err) {
  // EXPECT-NEXT: clean
  process.stderr.write(err.stack)
}
