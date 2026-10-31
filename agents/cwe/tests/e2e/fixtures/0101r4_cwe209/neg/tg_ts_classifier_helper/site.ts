import { InputError } from "./errors";

function resolveInputErrorStatus(err: unknown): number | null {
  if (err instanceof InputError) {
    return 400;
  }
  const name = (err as { name?: unknown }).name;
  if (name !== "InputError" && name !== "AuthorizationError") {
    return null;
  }
  return name === "AuthorizationError" ? 403 : 400;
}

export async function invoke(req: any, res: any) {
  try {
    await tools.run(req.body);
  } catch (err) {
    const inputStatus = resolveInputErrorStatus(err);
    if (inputStatus !== null) {
      sendJson(res, inputStatus, { ok: false, error: { message: getErrorMessage(err) } }); // EXPECT: clean tg-classifier-helper
      return;
    }
    sendJson(res, 500, { ok: false, error: { message: "failed" } });
  }
}
