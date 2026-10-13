import fs from "fs";

export async function gatherBody(request: Incoming): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of request) {
    // EXPECT-NEXT: finding P9
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

export async function drain(reader: Reader): Promise<Uint8Array[]> {
  const parts: Uint8Array[] = [];
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    // EXPECT-NEXT: finding P10
    parts.push(value);
  }
  return parts;
}

export function list(dir: string): string[] {
  const out: string[] = [];
  for (const e of fs.readdirSync(dir)) {
    // EXPECT-NEXT: clean N11
    out.push(e);
  }
  return out;
}

export function copy(items: string[]): string[] {
  const out: string[] = [];
  for (const x of items) {
    // EXPECT-NEXT: clean N12
    out.push(x);
  }
  return out;
}
