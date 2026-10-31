export async function invoke(req: any, res: any) {
  try {
    await tools.run(req.body);
  } catch (e) {
    if (e instanceof InputError) {
      res.status(400).json({ message: "invalid request" });
    } else {
      res.status(500).json({ message: e.message }); // EXPECT: finding tp-ts-else-of-caller-class-guard
    }
  }
}
