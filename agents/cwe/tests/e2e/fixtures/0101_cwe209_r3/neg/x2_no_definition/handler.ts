import { loadLedger, loadCoded, loadDetail } from "./svc/store";
import { loadTwice } from "./dup/a";
export async function handler(req: any, res: any) {
  const a = await loadLedger(req.query.id);
  if (!a.ok) return res.status(500).json({ error: a.error }); // probe tp-X2-crossfile-producer
  const b = await loadCoded(req.query.id);
  if (!b.ok) return res.status(500).json({ error: b.error }); // probe clean-X2-returned-code
  const c = await loadTwice(req.query.id);
  if (!c.ok) return res.status(500).json({ error: c.error }); // probe clean-X2-two-definitions
  const d = await loadDetail(req.query.id);
  if (!d.ok) return res.status(500).json({ message: d.message }); // probe clean-X2-detail-word-K
  const e = await loadLedger(req.query.id);
  if (!e.ok) return sendJsonError(res, 500, e.error); // probe gap-X2-C1-crossfile-helper-K14
  const f = await loadUnknown(req.query.id);
  return res.status(500).json({ error: f.error }); // EXPECT: clean clean-n04-no-definition
}
