export function onMsg(ws: any, raw: string) {
  try { JSON.parse(raw); } catch (err) {
    // EXPECT-NEXT: finding  websocket send of raw error message
    ws.send(JSON.stringify({ type: 'error', message: err.message }));
  }
}
