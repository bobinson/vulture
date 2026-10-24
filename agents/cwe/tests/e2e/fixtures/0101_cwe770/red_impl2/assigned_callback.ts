export function attach(ws: WebSocket): () => string {
  let log = "";
  ws.onmessage = (ev) => {
    // EXPECT-NEXT: finding every message appended in an assigned message callback
    log += ev.data;
  };
  return () => log;
}

export function click(button: HTMLElement): void {
  let clicks = 0;
  button.onclick = () => {
    // EXPECT-NEXT: clean a numeric counter in a click handler
    clicks += 1;
  };
}
