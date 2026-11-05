export async function h2(req: any, res: any) {
  try { await run(); } catch (err) {
    const body = { message: (err as Error).message };
    // EXPECT-NEXT: finding  detail carried via object built on prior line
    res.status(500).json(body);
  }
