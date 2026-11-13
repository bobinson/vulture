import { WebSocketServer } from "ws";
import { methods } from "./methods";

const wss = new WebSocketServer({ port: 8080 });
wss.on("connection", (socket) => {
  socket.on("message", async (raw) => {
    const call = JSON.parse(String(raw));
    const handler = (methods as Record<string, (p: Record<string, unknown>) => Promise<unknown>>)[call.method];
    socket.send(JSON.stringify(await handler(call.params)));
  });
});
