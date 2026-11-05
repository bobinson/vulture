try { run() } catch (err) {
  if (err instanceof HttpError) {
    // EXPECT-NEXT: finding  known-gap typed branch
    return res.status(err.status).json({ error: err.message })
  }
  res.status(500).json({ error: 'Internal error' })
}
