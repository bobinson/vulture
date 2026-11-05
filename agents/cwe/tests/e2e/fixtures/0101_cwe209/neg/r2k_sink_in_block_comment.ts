export function acknowledgeQuietly(req, res) {
  // EXPECT-NEXT: clean  a sink spelled in a block comment is not a sink
  if (req.query.quiet) /* res.send(err.message) */ res.send('ok');
}
