export async function invoke(req: any, res: any) {
  try {
    await tools.run(req.body);
  } catch (e) {
    if (e instanceof InputError) {
      return res.status(400).json({ trace: e.stack }); // EXPECT: finding tp-ts-stack-of-caller-class
    }
    res.status(500).json({ message: "failed" });
  }
}
