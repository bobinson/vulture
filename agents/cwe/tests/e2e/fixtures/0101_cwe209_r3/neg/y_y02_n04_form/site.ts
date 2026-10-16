import { load } from "./load";
export async function handler(req, res) {
  const outcome = await load(req.body.id);
  res.status(400).json({ error: outcome.error }); // EXPECT: clean clean-n04
  res.status(400).json({ message: outcome.errorCode }); // probe clean-code-field
}
