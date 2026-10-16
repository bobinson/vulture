try { run() } catch (problem) {
  const why = problem.message
  // EXPECT-NEXT: finding  renamed binding detail
  res.status(500).send(why)
}
