// R8 dev script reporting to its own stderr
for (const f of files) {
  try {
    lintFile(f);
  } catch (e) { // EXPECT: finding known-gap (residual, still reported): R8a CLI stderr.write + exitCode
    process.stderr.write(`lint failed: ${e.message}\n`);
    process.exitCode = 1;
  }
}
