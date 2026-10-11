try { run() } catch (err) {
  // EXPECT-NEXT: finding  object assign
  res.status(500).json(Object.assign({}, err))
}
