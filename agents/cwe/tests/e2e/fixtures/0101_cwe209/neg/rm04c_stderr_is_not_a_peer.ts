export function cli(err: Error) {
  // EXPECT-NEXT: clean  stderr is not a peer
  process.stderr.write(`${err.message}\n`);
}
