export async function show(req: any, res: any) {
  try {
    await store.read(req.params.id);
  } catch (err) {
    if (err instanceof InputError) {
      const dbErr = await db.lastError();
      res.status(400).json({ error: dbErr.message }); // EXPECT: finding tp-ts-other-error-in-guard
      return;
    }
  }
}
