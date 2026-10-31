export async function listEntries(store: any, probe: (name: string) => Promise<boolean>) {
  const registry = await store.read();
  const results: Array<{ name: string; live: boolean }> = [];
  for (const entry of registry.entries) {
    const live = await probe(entry.name);
    // EXPECT-NEXT: clean entries of a record already read into memory
    results.push({ name: entry.name, live });
  }
  return results;
}
