import { loadAccount } from './accounts';
export class HttpError extends Error {
  constructor(status, error) { super(); this.status = status; this.error = error; }
}
export async function show(req, res) {
  const result = await loadAccount(req.params.id);
  if (!result.ok) return res.status(404).json({ error: result.error }); // EXPECT: clean clean-crossfile-code
  res.json(result.data);
}
