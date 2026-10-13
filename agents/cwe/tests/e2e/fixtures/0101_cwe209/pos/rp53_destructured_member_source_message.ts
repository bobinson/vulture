export async function relayQuote(req, res) {
  const reply = await quoteClient.request(req.body);
  const { error } = reply.body;
  // EXPECT-NEXT: finding  destructured from a member source, message written
  if (error) res.status(500).json({ reason: error.message });
}
