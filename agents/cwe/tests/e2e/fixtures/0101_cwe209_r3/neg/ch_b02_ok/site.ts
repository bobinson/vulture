import type { ServerResponse } from "node:http";
function sendJson(res: ServerResponse, status: number, body: unknown) {
  res.statusCode = status;
  res.end(JSON.stringify(body));
}
export async function publish(req, res) {
  try {
    await relay.publish(req.body);
  } catch (err) {
    sendJson(res, 500, { ok: false, error: `Publish failed: ${String(err)}` }); // probe tp-H-ts
    return;
  }
  sendJson(res, 200, { ok: true }); // EXPECT: clean clean-ok
}
