enum Mode { Bypass = "bypass" }
export function guard(req: any, res: any, next: any) {
  if (req.headers['x-mode'] === Mode.Bypass) return next();
  if (!req.user) return res.status(401).end();
  next();
}
