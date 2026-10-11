export async function body(request) {
  const chunks = [];
  // EXPECT-NEXT: finding one-line loop
  for await (const chunk of request) chunks.push(chunk);
  return chunks;
}
export async function body2(request) {
  const chunks = [];
for await (const chunk of request) {
// EXPECT-NEXT: finding flat (unindented) body
chunks.push(chunk);
}
  return chunks;
}
