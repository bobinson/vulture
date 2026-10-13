class Outcome {
  constructor(ok, error) { this.ok = ok; this.error = error; }
}
function load(id) {
  if (!store.has(id)) return new Outcome(false, 'E_NOT_FOUND');
  return new Outcome(true);
}
app.get('/ledger/:id', (req, res) => {
  const outcome = load(req.params.id);
  res.status(404).json({ error: outcome.error }); // EXPECT: clean clean-code
});
