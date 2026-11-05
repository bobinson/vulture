export async function readCapped(body: ReadableStream<Uint8Array>, maxBytes: number) {
  const reader = body.getReader();
  const pieces: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }
    if (value?.length) {
      total += value.length;
      if (total > maxBytes) {
        try {
          await reader.cancel();
        } catch {}
        throw new Error("too large");
      }
      // EXPECT-NEXT: clean cap block exits two lines below the cap
      pieces.push(value);
    }
  }
  return pieces;
}

export async function startAll(cfg: { hostSpec: string }) {
  const servers: string[] = [];
  const hosts = await resolveListenHosts(cfg.hostSpec);
  for (const h of hosts) {
    await startListener(h);
    // EXPECT-NEXT: clean `listen` inside a longer callee name is not a pull
    servers.push(h);
  }
  return servers;
}

export function fromTail(step: { stdoutTail?: string[] }) {
  const out: string[] = [];
  const shas = step.stdoutTail ?? [];
  for (const s of shas) {
    // EXPECT-NEXT: clean `stdoutTail` head noun is tail, not a stream
    out.push(s);
  }
  return out;
}

export function bodyWithLimit(req: any, maxSize: number) {
  return new Promise((resolve, reject) => {
    const parts: Buffer[] = [];
    let size = 0;
    req.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > maxSize) {
        req.destroy();
        reject(new Error("too large"));
        return;
      }
      // EXPECT-NEXT: clean callback cap
      parts.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(parts)));
  });
}

export function sniffHead(res: any) {
  const sniff: Buffer[] = [];
  let sniffLen = 0;
  res.on("data", (chunk: Buffer) => {
    if (sniffLen < 16384) {
      // EXPECT-NEXT: clean guard cap
      sniff.push(chunk);
      sniffLen += chunk.length;
    }
  });
}

export async function readBytesCapped(reader: any, maxBytes: number) {
  const parts: string[] = [];
  let seen = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    if (seen + value.byteLength > maxBytes) {
      break;
    }
    seen += value.byteLength;
    // EXPECT-NEXT: clean byteLength running total
    parts.push(String(value));
  }
  return parts;
}

export function bodyNoLimit(req: any) {
  const parts: Buffer[] = [];
  // EXPECT-NEXT: finding uncapped data callback
  req.on("data", (chunk: Buffer) => parts.push(chunk));
  return parts;
}

export function lineBuffer(sock: any, onLine: (l: string) => void) {
  let pending = "";
  sock.on("data", (chunk: string) => {
    // EXPECT-NEXT: finding partial-line buffer with no maximum line length
    pending += chunk;
    let idx = pending.indexOf("\n");
    while (idx !== -1) {
      onLine(pending.slice(0, idx));
      pending = pending.slice(idx + 1);
      idx = pending.indexOf("\n");
    }
  });
}
