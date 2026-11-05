async function load(id: string) {
  try {
    await db.get(id);
    return { ok: true as const };
  } catch (e) {
    return { ok: false as const, error: (e as Error).message };
  }
}

export async function GET(req: Request) {
  const r = await load("x");
  if (!r.ok) return NextResponse.json({ error: r.error }, { status: 500 }); // probe tp-next
  const r2 = await load("y");
  if (!r2.ok) return Response.json({ error: r2.error }, { status: 500 }); // EXPECT: finding tp-response-json
  const r3 = await load("z");
  if (!r3.ok) return new Response(JSON.stringify({ error: r3.error }), { status: 500 }); // probe tp-new-response
  const r4 = await load("w");
  if (!r4.ok) return NextResponse.json(r4, { status: 500 }); // probe tp-next-whole
  return NextResponse.json({ ok: true });
}

export default async function handler(req: any, res: any) {
  const r = await load("x");
  if (!r.ok) return res.status(500).json({ error: r.error }); // probe tp-express-control
}
