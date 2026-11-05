export async function stream(req: any, res: any) {
  for await (const event of source()) {
    if (event.type === 'error') {
      res.write(JSON.stringify({ error: String(event.error) })); // EXPECT: finding
    }
  }
}
