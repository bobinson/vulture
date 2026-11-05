export async function quote(req, res) {
  const reply = await fetch(PRICING_URL, { method: 'POST', body: JSON.stringify(req.body) });
  const payload = await reply.json();
  if (!reply.ok) return res.status(502).json({ error: payload.error }); // EXPECT: clean ambiguous-upstream
  res.json(payload);
}
