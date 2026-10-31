class Outcome {
  constructor(
    public readonly ok: boolean,
    public readonly error?: string,
  ) {}
}
async function load(id: string): Promise<Outcome> {
  try { await store.read(id); return new Outcome(true); }
  catch (e: any) { return new Outcome(false, e.message); }
}
export async function show(req, res) {
  const o = await load(req.params.id);
  if (!o.ok) return res.status(500).json({ error: o.error }); // EXPECT: finding tp-F3-ts-multiline-ctor
}
