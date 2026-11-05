try { run() } catch (err) {
  const errorDetail = util.inspect(err, { depth: 5 })
  // EXPECT-NEXT: finding  inspect with opts
  res.status(500).send(errorDetail)
}
