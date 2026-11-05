// CWE-918 three hops: req.query.url is assigned, passed through a same-file helper, and the helper's return value is fetched.
function toTarget(raw: string): string {
  const trimmed = raw.trim();
  return trimmed;
}

export async function handler(req: Request, res: Response): Promise<void> {
  const raw = req.query.url;
  const target = toTarget(raw);
  const reply = await fetch(target);
  res.end(await reply.text());
}
