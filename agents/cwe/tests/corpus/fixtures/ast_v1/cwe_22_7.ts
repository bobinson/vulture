// pins: a conditional sanitiser (if (strict) p = path.basename(p)) joins with the raw branch, so fs.readFile(p) still reports
export function handler(req: any, strict: boolean): void {
  let p: string = req.query.f;
  if (strict) p = path.basename(p);
  fs.readFile(p, () => {});
}
