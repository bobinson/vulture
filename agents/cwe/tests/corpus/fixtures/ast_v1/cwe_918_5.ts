// CWE-918 default-value idiom: t = req.query.url is replaced by a constant only when empty, so the external origin survives the join into http.get(t).
export function handler(req: Request, res: Response): void {
  let t = req.query.url;
  if (!t) t = "http://localhost/health";
  http.get(t);
  res.end();
}
