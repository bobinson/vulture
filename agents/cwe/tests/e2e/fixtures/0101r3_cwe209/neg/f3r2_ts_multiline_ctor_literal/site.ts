class Outcome {
  constructor(
    public readonly ok: boolean,
    public readonly error?: string,
  ) {}
}
async function load(id: string): Promise<Outcome> {
  try { await store.read(id); return new Outcome(true); }
  catch (e: any) { logger.warn(e.message); return new Outcome(false, "LOAD_FAILED"); }
}
export async function show(req, res) {
  const o = await load(req.params.id);
  if (!o.ok) return res.status(500).json({ error: o.error }); // EXPECT: clean literal-code-multiline-ctor
}
