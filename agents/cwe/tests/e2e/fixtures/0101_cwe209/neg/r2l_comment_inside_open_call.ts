export function acknowledgeLater(req, res) {
  // EXPECT-NEXT: clean  a comment on a continuation line of the call is not an argument
  res.json({
    ok: true, // was: detail: err.message
  });
}
