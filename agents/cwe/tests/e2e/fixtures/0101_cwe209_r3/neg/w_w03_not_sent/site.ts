export async function handler(req, res) {
  const job = { id: 1 } as any;
  try { await run(); } catch (err) {
    job.error = err.message; // EXPECT: clean clean-W-not-sent
    await db.save(job);
  }
  res.json({ id: job.id }); // probe clean-member-read
}
