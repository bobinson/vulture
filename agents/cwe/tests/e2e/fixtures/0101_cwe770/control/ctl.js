async function lines(stream) {
  const out = [];
  for await (const line of stream) {
    // EXPECT-NEXT: finding C27 control for E27 (name 'stream')
    out.push(line);
  }
  return out;
}

async function pump(reader) {
  const parts = [];
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    // EXPECT-NEXT: finding C28 control for E28 (multi-line)
    parts.push(value);
  }
  return parts;
}
