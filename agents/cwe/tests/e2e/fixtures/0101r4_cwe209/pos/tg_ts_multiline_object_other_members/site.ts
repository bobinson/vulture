import { ValidationError } from "./errors";
export async function save(req: any, res: any) {
  try {
    await repo.save(req.body);
  } catch (e: any) {
    if (e instanceof ValidationError) {
      return res.status(400).json({ // EXPECT: finding tp-ts-multiline-own-and-other-members
        error: e.message,
        sql: e.query,
      });
    }
    return res.status(500).json({ error: "internal" });
  }
}
