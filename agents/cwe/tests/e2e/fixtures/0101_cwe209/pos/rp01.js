function sendFailure(res, err) {
  // EXPECT-NEXT: finding
  res.status(500).send(err)
}
