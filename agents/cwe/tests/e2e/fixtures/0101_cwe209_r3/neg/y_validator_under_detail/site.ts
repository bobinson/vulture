export default async function handler(req: any, res: any) {
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ message: parsed.error }); // probe fp-Y-safeparse
  }
  const v = validateInput(req.body);
  if (v.error) {
    return res.status(400).json({ detail: v.error }); // EXPECT: clean fp-Y-validate
  }
  const r = await svc.doThing(parsed.data);
  if (!r.ok) {
    return res.status(500).json({ message: r.error }); // probe Y-crossfile-nocode
  }
  return res.json(r);
}
