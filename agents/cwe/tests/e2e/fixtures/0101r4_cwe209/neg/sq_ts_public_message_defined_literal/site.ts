function toPublicMessage(err: unknown): string {
  if (err instanceof Error && err.name === "TimeoutError") {
    return "The service is busy, try again.";
  }
  return "Something went wrong.";
}

export async function show(req: any, res: any) {
  try {
    await store.read(req.params.id);
  } catch (err) {
    res.status(500).json({ error: toPublicMessage(err) }); // EXPECT: clean sq-defined-sanitiser-returns-literals
  }
}
