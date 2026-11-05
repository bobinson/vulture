export async function pump(reader: any, writer: any, metrics: any) {
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    await writer.write(value);
    // EXPECT-NEXT: clean a metric incremented by a size
    metrics.add(value.length);
  }
}

export async function keep(reader: any, seen: Set<Uint8Array>) {
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    // EXPECT-NEXT: finding peer data added to a set
    seen.add(value);
  }
}
