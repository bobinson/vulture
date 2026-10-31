function sendError(res, err) {
  logger.error(err);
  res.status(500).json({ error: 'INTERNAL' });
}
export async function show(req, res) {
  try { await store.read(req.params.id); }
  catch (err) { sendError(res, err); } // EXPECT: clean clean-samefile-sanitiser
}
