import { formatFailure, formatQuotaCode, formatQuiet } from "./lib/fmt";
import { formatAmbiguous } from "./dup/a";
export async function handler(req: any, res: any) {
  try {
    await work();
  } catch (err) {
    if (req.a) return res.status(500).json({ error: formatFailure(err) }); // probe tp-X-crossfile-renderer
    if (req.b) return res.status(500).json({ error: formatQuotaCode(err) }); // EXPECT: clean clean-X-classifier-literals
    if (req.c) return res.status(500).json({ error: formatQuiet(err) }); // probe clean-X-log-only
    if (req.d) return res.status(500).json({ error: formatAmbiguous(err) }); // probe clean-X-two-definitions
    return res.status(500).json({ error: formatUndefinedHere(err) }); // probe clean-X-no-definition-n08
  }
}
