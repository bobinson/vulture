export async function show(req: any, res: any) {
  try {
    await store.read(req.params.id);
  } catch (err) {
    if (err instanceof ValidationError) {
      const inner = err.cause as Error;
      res.status(400).json({ error: inner.message }); // EXPECT: finding tp-ts-binding-from-cause
    }
  }
}
