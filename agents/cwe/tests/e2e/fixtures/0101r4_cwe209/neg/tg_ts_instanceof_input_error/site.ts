class InputError extends Error {}

export async function invoke(req: any, res: any) {
  try {
    await tools.run(req.body);
  } catch (e) {
    if (e instanceof InputError) {
      return res.status(400).json({ message: e.message }); // EXPECT: clean tg-instanceof-input-class
    }
    res.status(500).json({ message: "failed" });
  }
}
