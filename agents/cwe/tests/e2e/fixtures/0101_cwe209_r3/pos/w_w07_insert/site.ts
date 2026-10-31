export default async function handler(request, response) {
  const results: any[] = [];
  for (const focus of items) {
    try { results.push(await run(focus)); }
    catch (error) {
      results.push({ // EXPECT: finding tp-W-insert
        id: focus.id,
        reason: error instanceof Error ? error.message : "Unknown error",
      });
    }
  }
  response.status(200).json({ results });
}
