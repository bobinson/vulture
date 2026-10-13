type Result = { ok: true } | { ok: false; error: string };

async function load(id: string): Promise<Result> {
  try {
    await db.get(id);
    return { ok: true };
  } catch (e) {
    return { ok: false, error: (e as Error).message };
  }
}

export async function GET(req: Request, res: any) {
  const r = await load("x");
  if (!r.ok) return res.status(500).json(r); // probe tp-ts-whole-result
  const r2 = await load("y");
  if (!r2.ok) return res.status(500).json({ ...r2 }); // EXPECT: clean tp-ts-spread
}
