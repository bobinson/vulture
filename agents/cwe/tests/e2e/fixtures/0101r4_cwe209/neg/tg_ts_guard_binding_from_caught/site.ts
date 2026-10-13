export async function show(req: any, res: any) {
  try {
    await store.read(req.params.id);
  } catch (err) {
    if (err instanceof InputError) {
      const detail = err.message;
      res.status(400).json({ error: detail }); // EXPECT: clean tg-binding-from-caught
      return;
    }
    res.status(500).json({ error: "failed" });
  }
}
