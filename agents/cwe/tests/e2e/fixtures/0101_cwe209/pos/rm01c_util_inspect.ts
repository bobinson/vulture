}
export async function h3(req: any, res: any) {
  try { await run(); } catch (err) {
    // EXPECT-NEXT: finding  util inspect
    res.end(JSON.stringify(err, Object.getOwnPropertyNames(err)));
  }
