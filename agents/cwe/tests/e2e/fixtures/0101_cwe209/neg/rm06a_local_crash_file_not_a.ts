export async function dump(err) {
  try { await run(); } catch (err) {
    // EXPECT-NEXT: clean  local crash file not a peer
    await fs.promises.writeFile(crashPath, String(err));
  }
}
