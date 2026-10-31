export async function upload(req: any, res: any) {
  try {
    await store.put(req.body);
  } catch (err) {
    const text = String(err);
    if (text.includes("too large")) {
      sendJsonError(res, 413, text); // EXPECT: clean clean-T
      return;
    }
    sendJsonError(res, 500, "internal");
  }
}
