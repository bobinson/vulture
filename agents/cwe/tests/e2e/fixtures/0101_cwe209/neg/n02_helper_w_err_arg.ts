export function send(res, err: HandlerError, extra) {
  // EXPECT-NEXT: clean  helper w err arg
  res.status(err.code).json(catalogEnvelope(err, extra));
}
