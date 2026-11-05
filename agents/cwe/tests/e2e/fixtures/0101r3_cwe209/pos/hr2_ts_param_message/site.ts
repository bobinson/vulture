function fail(res: any, e: Error) {
  res.status(500).send(e.message);
}
export async function h(req, res) {
  try {
    await work();
  } catch (err) {
    fail(res, err); // EXPECT: finding tp-H-ts-param-message
  }
}
