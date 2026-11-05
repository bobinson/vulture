import { ValidationError } from "./errors";
export async function save(req: any, res: any) {
  try {
    await repo.save(req.body);
  } catch (e) {
    if (e instanceof ValidationError) {
      return res.status(400).json({ error: e.parent.message }); // EXPECT: finding tp-ts-own-member-parent
    }
    return res.status(500).json({ error: "internal" });
  }
}
