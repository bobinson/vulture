export async function show(req: any, res: any) {
  try {
    await store.read(req.params.id);
  } catch (err) {
    res.status(500).json({ error: toPublicMessage(err) }); // EXPECT: clean sq-public-qualifier-no-definition
  }
}
