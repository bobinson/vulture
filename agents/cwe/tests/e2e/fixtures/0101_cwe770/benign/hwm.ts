export async function capped(stream: AsyncIterable<Buffer>, highWaterMark: number): Promise<Buffer[]> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of stream) {
    size += chunk.length;
    if (size > highWaterMark) throw new Error("too large");
    // EXPECT-NEXT: clean F22 cap named highWaterMark (not in the cap vocabulary)
    chunks.push(chunk);
  }
  return chunks;
}

export async function capped2(stream: AsyncIterable<Buffer>, limits: { body: number }): Promise<Buffer[]> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of stream) {
    size += chunk.length;
    if (size > limits.body) throw new Error("too large");
    // EXPECT-NEXT: clean F23 cap named limits.body (plural word)
    chunks.push(chunk);
  }
  return chunks;
}

export async function capped3(stream: AsyncIterable<Buffer>, MAXBYTES: number): Promise<Buffer[]> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of stream) {
    size += chunk.length;
    if (size > MAXBYTES) throw new Error("too large");
    // EXPECT-NEXT: clean F24 all-caps fused MAXBYTES
    chunks.push(chunk);
  }
  return chunks;
}
