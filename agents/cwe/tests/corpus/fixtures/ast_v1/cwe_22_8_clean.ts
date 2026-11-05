// pins: an early-exit containment guard on the sink value (if (!resolved.startsWith(root)) return) declines fs.readFile(resolved)
export function handler(req: any): void {
  const root = "/srv/docs/";
  const resolved = path.resolve(root, req.query.f);
  if (!resolved.startsWith(root)) return;
  fs.readFile(resolved, () => {});
}
