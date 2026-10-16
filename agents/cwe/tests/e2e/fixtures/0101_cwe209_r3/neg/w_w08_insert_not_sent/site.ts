export default async function handler(request, response) {
  const failures: string[] = [];
  for (const f of items) {
    try { await run(f); } catch (error) { failures.push(error.message); } // EXPECT: clean clean-W-insert-not-sent
  }
  logger.warn({ failures });
  response.status(200).json({ count: failures.length });
}
