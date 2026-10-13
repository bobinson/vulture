export async function invoke(req: any, res: any) {
  try {
    await tools.run(req.body);
  } catch (e) {
    if (e instanceof DatabaseError) {
      return res.status(503).json({ message: e.message }); // EXPECT: finding tp-ts-instanceof-internal
    }
    res.status(500).json({ message: "failed" });
  }
}
