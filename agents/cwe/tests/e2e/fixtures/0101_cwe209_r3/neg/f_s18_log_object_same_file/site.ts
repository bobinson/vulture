async function prune(userId) {
  try { await queue.add({ userId }); } catch (err) {
    console.error('prune failed', {
      error: err instanceof Error ? err.message : err,
    });
  }
}
export async function verify(req, res) {
  const applied = await applyProof(req.body);
  if (!applied.ok) return res.status(applied.status).json({ error: applied.error }); // EXPECT: clean clean-crossfile-codes
}
