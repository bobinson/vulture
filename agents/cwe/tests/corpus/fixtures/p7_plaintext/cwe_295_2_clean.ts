import { WebSocket } from "ws";

export function connect(endpoint: string): WebSocket {
  const wsOptions: Record<string, unknown> = { maxPayload: 1024 * 1024 };
  wsOptions.rejectUnauthorized = true;
  return new WebSocket(endpoint, wsOptions);
}
