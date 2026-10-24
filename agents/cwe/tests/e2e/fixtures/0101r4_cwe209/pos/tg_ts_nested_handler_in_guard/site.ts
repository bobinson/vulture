export async function show(req: any, res: any) {
  try {
    await store.read(req.params.id);
  } catch (err) {
    if (err instanceof InputError) {
      try {
        await db.save(req.body);
      } catch (dbErr) {
        res.status(500).json({ error: dbErr.message }); // EXPECT: finding tp-ts-nested-handler
      }
    }
  }
}
