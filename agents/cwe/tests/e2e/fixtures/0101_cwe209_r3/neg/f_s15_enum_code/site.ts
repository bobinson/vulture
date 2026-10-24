function charge(card) {
  if (!card.valid) return { ok: false, error: PaymentError.DECLINED };
  return { ok: true };
}
export function pay(req, res) {
  const outcome = charge(req.body.card);
  if (!outcome.ok) return res.status(402).json({ error: outcome.error }); // EXPECT: clean clean
}
