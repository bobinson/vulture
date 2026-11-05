export async function GET(req: Request) {
  try { await x(); } catch (e) {
    return new Response(JSON.stringify({ error: (e as Error).message }), { status: 500 }); // EXPECT: clean ctl-new-response
  }
}
