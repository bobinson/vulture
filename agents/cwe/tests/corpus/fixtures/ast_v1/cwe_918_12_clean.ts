// CWE-918 clean: req.query.url passes through an ssrf-named sanitiser call (ssrfGuard) before it is fetched.
export async function handler(req: Request, res: Response): Promise<void> {
  const target = ssrfGuard(req.query.url);
  const reply = await fetch(target);
  res.end(await reply.text());
}
