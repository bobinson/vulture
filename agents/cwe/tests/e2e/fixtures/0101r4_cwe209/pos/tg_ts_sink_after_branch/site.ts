export async function invoke(req: any, res: any) {
  try {
    await tools.run(req.body);
  } catch (e) {
    if (e instanceof InputError) {
      audit.note("input refused");
    }
    res.status(500).json({ message: e.message }); // EXPECT: finding tp-ts-sink-outside-branch
  }
}
