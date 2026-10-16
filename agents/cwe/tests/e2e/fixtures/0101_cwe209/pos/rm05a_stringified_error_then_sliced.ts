export function a(res: any) {
  try { run(); } catch (err) {
    // EXPECT-NEXT: finding  stringified error then sliced
    res.send(String(err).slice(0, 500));
  }
}
