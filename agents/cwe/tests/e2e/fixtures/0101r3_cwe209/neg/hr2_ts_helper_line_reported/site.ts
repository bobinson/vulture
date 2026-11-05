function fail(res: any, err: Error) {
  res.status(500).send(err.message);
}
export async function h(req, res) {
  try {
    await work();
  } catch (err) {
    fail(res, err); // EXPECT: clean the-helper-line-is-the-report
  }
}
