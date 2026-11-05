main().catch((err) => {
  // EXPECT-NEXT: clean  node stderr cli
  process.stderr.write(`${err.message}\n`)
  process.exit(1)
})
