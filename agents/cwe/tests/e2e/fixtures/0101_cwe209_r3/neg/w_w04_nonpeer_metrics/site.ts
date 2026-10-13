export async function handler(req, res) {
  const metrics = { n: 0 } as any;
  try { await run(); } catch (err) { metrics.lastError = err.message; } // EXPECT: clean clean-W-nonpeer
  res.json(metrics);
}
