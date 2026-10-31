import { jsonError } from "./utils";
export async function handleRouteError(res, err) {
  jsonError(res, 500, String(err)); // EXPECT: finding tp-C-ts
}
export async function tabs(req, res) {
  try { await browser.tabs(); } catch (err) { jsonError(res, 500, String(err)); } // probe tp-C-ts2
}
