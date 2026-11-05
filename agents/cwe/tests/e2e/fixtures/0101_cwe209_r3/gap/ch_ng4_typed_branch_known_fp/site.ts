export async function invoke(req: any, res: any) {
  try {
    await tools.invoke(req.body);
  } catch (err) {
    if (err instanceof ArgumentShapeError) {
      sendJsonError(res, 400, err.message); // EXPECT: finding fp-NG4-typed-branch
      return;
    }
    sendJsonError(res, 500, "internal");
  }
}
