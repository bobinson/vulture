async function load(id: string) {
  try {
    await db.get(id);
  } catch (e) {
    throw new HttpError(500, e);
  }
  return remote.lookup(id);
}

export default async function handler(req: any, res: any) {
  const out = await load(req.query.id);
  if (!out.ok) return res.status(502).json({ error: out.error }); // EXPECT: clean clean-Q-throw
}
