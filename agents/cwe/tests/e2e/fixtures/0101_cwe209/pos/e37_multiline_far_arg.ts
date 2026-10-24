try { run() } catch (err) {
  // EXPECT-NEXT: finding  multiline far arg
  res.status(500).json({
    ok: false,
    code: 'E1',
    when: Date.now(),
    path: req.path,
    method: req.method,
    requestId: req.id,
    detail: err.message,
  })
}
