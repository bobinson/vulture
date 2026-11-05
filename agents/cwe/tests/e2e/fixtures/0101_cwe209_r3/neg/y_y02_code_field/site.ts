import { load } from "./load";
export async function handler(req, res) {
  const outcome = await load(req.body.id);
  res.status(400).json({ error: outcome.error }); // probe clean-n04
  res.status(400).json({ message: outcome.errorCode }); // EXPECT: clean clean-code-field
}
