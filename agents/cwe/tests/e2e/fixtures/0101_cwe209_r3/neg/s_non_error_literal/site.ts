export async function chat(req: any, res: any) {
  for await (const event of agent.stream(req.body)) {
    if (event.type === 'progress') {
      res.write(JSON.stringify({ error: String(event.error) })); // EXPECT: clean clean-S-non-error-literal
    }
  }
}
