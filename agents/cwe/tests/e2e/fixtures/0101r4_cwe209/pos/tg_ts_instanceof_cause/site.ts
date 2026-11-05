export async function show(req: any, res: any) {
  try {
    await store.read(req.params.id);
  } catch (err) {
    if (err instanceof ValidationError) {
      res.status(400).json({ error: String(err.cause) }); // EXPECT: finding tp-ts-wrapped-cause
      return;
    }
    res.status(500).json({ error: "failed" });
  }
}
