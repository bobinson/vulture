export async function chat(req, res) {
  for await (const event of agent.stream(req.body)) {
    switch (event.type) {
      case 'text':
        res.write(JSON.stringify({ text: event.text })); // EXPECT: clean
        break;
      case 'error':
        res.write(JSON.stringify({ error: String(event.error) })); // probe tp-S
        break;
    }
  }
  res.end();
}
