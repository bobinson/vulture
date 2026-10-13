import { ValidationError } from "./errors";
export async function save(req: any, res: any) {
  try {
    await repo.save(req.body);
  } catch (err) {
    if (err instanceof ValidationError) {
      return res.status(400).json(err); // EXPECT: finding tp-ts-whole-error-object-serialised
    }
    return res.status(500).json({ error: "internal" });
  }
}
