try { run() } catch (err) {
  // EXPECT-NEXT: clean  message lookup table
  res.status(400).json({ error: PUBLIC_MESSAGES[err.message] ?? 'Request failed' })
}
