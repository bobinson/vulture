function statusOf(err: unknown): number {
  if (err instanceof InputError) {
    return 400;
  }
  return 500;
}

export async function invoke(req: any, res: any) {
  try {
    await tools.run(req.body);
  } catch (err) {
    const status = statusOf(err);
    if (status) {
      sendJson(res, status, { ok: false, error: { message: getErrorMessage(err) } }); // EXPECT: finding tp-ts-classifier-answers-every-error
      return;
    }
  }
}
