export async function invoke(req: any, res: any) {
  try {
    await tools.run(req.body);
  } catch (err) {
    if (err.name === "AuthorizationError") {
      return res.status(403).json({ message: err.message }); // EXPECT: clean tg-name-check
    }
    return res.status(500).json({ message: "failed" });
  }
}
