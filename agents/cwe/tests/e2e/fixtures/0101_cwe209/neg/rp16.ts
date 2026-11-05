try { run() } catch (err) {
  // EXPECT-NEXT: clean
  fs.writeFileSync("crash.log", err.stack)
}
