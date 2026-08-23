// floor.ts -- 0076 fixture: the quote is `});`. Three characters, ZERO tokens.
// 91% of such lines are non-unique inside a single real file, which is why the
// signal floor exists: a needle this small cannot discriminate a location.
export const handler = withAuth(async (req, res) => {
  res.json({ ok: true });
});
