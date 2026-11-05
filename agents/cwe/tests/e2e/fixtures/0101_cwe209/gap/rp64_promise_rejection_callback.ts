export function priceRoute(req, res) {
  priceQuote(req.body).then(
    (quote) => res.json(quote),
    // EXPECT-NEXT: clean  known-gap a rejection-callback parameter is not error-named
    (reason) => res.status(500).json({ reason: reason.message }),
  );
}
