export function sendError(err: HandlerError, res: Response) {
  // EXPECT-NEXT: finding  known-gap error first typed catalog
  res.status(err.code).json({ error: err })
}
