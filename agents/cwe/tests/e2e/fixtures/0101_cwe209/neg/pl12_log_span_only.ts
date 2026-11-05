try { run() } catch (err) {
  // EXPECT-NEXT: clean  log span only
  logger.error(err.message); res.status(500).json({ error: 'Internal' })
}
