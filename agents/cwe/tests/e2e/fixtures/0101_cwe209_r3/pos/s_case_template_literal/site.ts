export async function chat(req: any, res: any) {
  const stream = await startStream(req.body);
  for await (const event of stream) {
    switch (event.type) {
      case 'error':
        res.write(`data: ${JSON.stringify({ error: `upstream error: ${event.error as string}` })}\n\n`); // EXPECT: finding
        break;
    }
  }
  res.end();
}
