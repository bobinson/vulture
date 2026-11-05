import { ValidationError } from "./errors";
export async function save(req: any, res: any) {
  try {
    await repo.save(req.body);
  } catch (e) {
    if (e instanceof ValidationError) {
      return res.status(400).json({ error: e.dbError.message }); // EXPECT: finding tp-ts-own-member-db-error
    }
    return res.status(500).json({ error: "internal" });
  }
}
