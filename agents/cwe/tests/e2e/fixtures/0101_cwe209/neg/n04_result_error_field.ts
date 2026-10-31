const outcome = await go();
// EXPECT-NEXT: clean  result error field
if (!outcome.ok) res.status(400).json({ error: outcome.error });
