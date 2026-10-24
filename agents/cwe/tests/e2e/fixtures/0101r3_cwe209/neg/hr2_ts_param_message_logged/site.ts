function fail(res: any, e: Error) {
  logger.error(e.message);
  res.status(500).send("internal error");
}
export async function h(req, res) {
  try {
    await work();
  } catch (err) {
    fail(res, err); // EXPECT: clean helper-logs-message-writes-literal
  }
}
