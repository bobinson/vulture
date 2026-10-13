export function collect(req: Req): Promise<Buffer> {
  const chunks: Buffer[] = []
  req.on('data', (chunk: Buffer) => {
    // EXPECT-NEXT: finding event-driven body accumulation
    chunks.push(chunk)
  })
  return done(chunks)
}
export async function readAll(reader: R) {
  const parts: Array<Uint8Array> = []
  while (true) {
    const { done, value } = await reader.read()
    if (done) break
    const maxSeen: Map<string, number> = new Map()
    // EXPECT-NEXT: finding generic + max-named unrelated local
    parts.push(value)
  }
  return parts
}
