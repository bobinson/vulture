function checkInput(body) {
  if (!body.name) return { error: 'name is required' };
  return { input: body };
}
export function create(req, res) {
  const verdict = checkInput(req.body);
  if ('error' in verdict) return res.status(400).json({ error: verdict.error }); // EXPECT: clean clean
  try { save(verdict.input); } catch (err) {
    res.status(500).json({ error: err.message }); // probe tp
  }
}
