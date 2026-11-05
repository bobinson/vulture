try { run() } catch (err) {
  // EXPECT-NEXT: finding  getOwnPropertyNames
  res.status(500).json(JSON.parse(JSON.stringify(err, Object.getOwnPropertyNames(err))))
}
