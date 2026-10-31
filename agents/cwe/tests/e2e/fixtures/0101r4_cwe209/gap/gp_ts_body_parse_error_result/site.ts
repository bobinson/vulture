// Known false positive: the reader's error is catalog text or the parser's
// diagnostic about the peer's OWN payload; local evidence cannot tell it from
// an internal failure carried in the same field.
async function readBody(req: any): Promise<{ ok: true; value: unknown } | { ok: false; error: string }> {
  try {
    return { ok: true, value: JSON.parse(await collect(req)) };
  } catch (e) {
    return { ok: false, error: (e as Error).message };
  }
}

export async function hook(req: any, res: any) {
  const b = await readBody(req);
  if (!b.ok) {
    res.statusCode = 400;
    res.end(b.error); // EXPECT: finding known-gap body-parse-error
  }
}
