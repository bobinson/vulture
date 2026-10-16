export function stream() {
  try { run(); } catch (e) {
    // EXPECT-NEXT: clean  local stderr
    process.stderr.write(e.message);
  }
}
