export async function invoke(req: any, res: any) {
  try {
    await tools.run(req.body);
  } catch (e) {
    if (e instanceof InputError || e instanceof StorageError) {
      return res.status(400).json({ message: e.message }); // EXPECT: finding tp-ts-or-guard
    }
    res.status(500).json({ message: "failed" });
  }
}
