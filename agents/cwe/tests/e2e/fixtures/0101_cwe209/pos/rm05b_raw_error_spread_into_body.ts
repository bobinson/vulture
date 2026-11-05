export function b(res: any) {
  try { run(); } catch (error) {
    // EXPECT-NEXT: finding  raw error spread into body
    res.json({ ok: false, ...error });
  }
}
