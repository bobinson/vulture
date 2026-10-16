import { InputError } from "./errors";
function statusFor(err: unknown, first: unknown): number | null {
  if (!(first instanceof InputError)) return null;
  return 400;
}
export async function save(req: any, res: any) {
  try {
    await repo.save(req.body);
  } catch (err) {
    const status = statusFor(err);
    if (status !== null) {
      return res.status(status).json({ error: getErrorMessage(err) }); // EXPECT: finding tp-ts-classifier-other-subject
    }
    return res.status(500).json({ error: "internal" });
  }
}
