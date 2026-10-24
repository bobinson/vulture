import { load } from "./load";
export async function show(req, res) {
  const r = await load(req.params.id);
  if (r.type === 'error') {
    res.write(r.error); // EXPECT: clean clean-S-no-iteration
  }
}
