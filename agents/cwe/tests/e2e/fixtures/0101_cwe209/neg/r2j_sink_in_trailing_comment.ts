export function acknowledge(req, res) {
  // EXPECT-NEXT: clean  a sink spelled in a trailing comment is not a sink
  res.send('ok'); // never res.send(err.message)
}
