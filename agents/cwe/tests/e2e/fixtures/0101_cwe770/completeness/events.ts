export function collect(req: any): Promise<Buffer> {
  const chunks: Buffer[] = [];
  return new Promise((resolve) => {
    req.on('data', (chunk: Buffer) => {
      // EXPECT-NEXT: finding node stream data event
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
  });
}
