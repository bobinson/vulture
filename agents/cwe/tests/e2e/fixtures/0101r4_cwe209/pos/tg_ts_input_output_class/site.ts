export async function invoke(req: any, res: any) {
  try {
    await files.read(req.body.path);
  } catch (e) {
    if (e instanceof InputOutputError) {
      return res.status(500).json({ message: e.message }); // EXPECT: finding tp-ts-io-class-is-internal
    }
  }
}
