function fill(target) { target.error = 'E_FAILED'; }
function audit(record) {
  try { run(); } catch (err) { record.error = err.message; } // EXPECT: clean clean-W-collision-record-not-sent
  return record;
}
export function handler(req, res) {
  const out: any = {};
  fill(out);
  res.json(out);
}
