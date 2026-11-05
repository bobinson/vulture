export function h(req, res) {
  // EXPECT-NEXT: clean  escaped-quote literal
  res.send('{\'error\' : \'Invalid\'}')
}
