function statusFor(err: any): number | null {
  if (err instanceof ValidationError) {
    return 400;
  }
  if (err.code === "ENOENT") {
    return 404;
  }
  return null;
}

export async function invoke(req: any, res: any) {
  try {
    await tools.run(req.body);
  } catch (err) {
    const status = statusFor(err);
    if (status !== null) {
      res.status(status).json({ error: getErrorMessage(err) }); // EXPECT: finding tp-ts-classifier-admits-a-code
      return;
    }
    res.status(500).json({ error: "failed" });
  }
}
