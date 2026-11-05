import { sendRouteError, Catalog, logError } from "./errors";
function bad(res, status, msg) { res.status(status).json({ error: msg }); }
export async function show(req, res) {
  try { await store.read(req.params.id); }
  catch (err) {
    logError(res, err); // probe clean-log-helper
    sendRouteError(res, Catalog.INTERNAL); // probe clean-catalog
    bad(res, 400, 'literal'); // EXPECT: clean clean-literal
    return;
  }
}
