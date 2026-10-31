function toPublicMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

export async function show(req: any, res: any) {
  try {
    await store.read(req.params.id);
  } catch (err) {
    res.status(500).json({ error: toPublicMessage(err) }); // EXPECT: finding tp-sanitiser-name-renders-message
  }
}
