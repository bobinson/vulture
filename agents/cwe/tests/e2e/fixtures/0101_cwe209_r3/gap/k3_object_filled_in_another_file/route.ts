import { fillReport } from "./lib/report";
export async function report(req: any, res: any) {
  const out: any = { ok: true };
  await fillReport(out, req.query.id);
  res.json(out); // EXPECT: clean gap-K3-object-filled-elsewhere
}
