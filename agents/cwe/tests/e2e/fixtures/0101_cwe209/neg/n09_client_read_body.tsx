// EXPECT-NEXT: clean  client read body
const body = (await res.json()) as { error?: string; message?: string };
