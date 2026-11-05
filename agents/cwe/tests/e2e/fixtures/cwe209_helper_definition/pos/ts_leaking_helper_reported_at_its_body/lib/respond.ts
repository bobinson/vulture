export function sendError(res: any, err: any) {
  res.status(500).json({ error: err.message }); // EXPECT: finding
}
