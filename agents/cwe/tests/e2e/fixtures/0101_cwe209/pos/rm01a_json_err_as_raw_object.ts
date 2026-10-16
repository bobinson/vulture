export async function handler(req: any, res: any) {
  try { await run(); } catch (err) {
    // EXPECT-NEXT: finding  json err as raw object via spread
    res.status(500).json({ ...err });
  }
}
