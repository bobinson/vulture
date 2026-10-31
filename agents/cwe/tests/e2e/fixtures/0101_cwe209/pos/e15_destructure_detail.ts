try { run() } catch (e) {
  const { message, stack } = e
  // EXPECT-NEXT: finding  destructure detail
  res.status(500).json({ message, stack })
}
