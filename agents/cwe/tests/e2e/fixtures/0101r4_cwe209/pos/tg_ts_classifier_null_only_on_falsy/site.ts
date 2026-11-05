function statusFor(err: unknown): number | null {
  if (!err) {
    return null;
  }
  if (err instanceof ValidationError) {
    return 400;
  }
  return 500;
}

export async function invoke(req: any, res: any) {
  try {
    await tools.run(req.body);
  } catch (err) {
    const status = statusFor(err);
    if (status !== null) {
      res.status(status).json({ error: getErrorMessage(err) }); // EXPECT: finding tp-ts-classifier-falls-through-to-answer
      return;
    }
  }
}
