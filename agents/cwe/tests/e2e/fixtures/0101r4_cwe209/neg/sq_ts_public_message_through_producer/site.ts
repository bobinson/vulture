async function loadRecord(id: string) {
  try {
    await db.get(id);
    return { ok: true as const };
  } catch (e) {
    return { ok: false as const, error: toPublicMessage(e) };
  }
}

export default async function handler(req: any, res: any) {
  const b = await loadRecord(req.query.id);
  if (!b.ok) return res.status(500).json({ error: b.error }); // EXPECT: clean sq-public-qualifier-producer
  return res.status(200).end();
}
