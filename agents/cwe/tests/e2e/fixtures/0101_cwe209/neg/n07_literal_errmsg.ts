function h(req, res) {
  const errMsg = { err: 'nope' }
  // EXPECT-NEXT: clean  literal errMsg
  return res.send(utils.toJson(errMsg))
}
