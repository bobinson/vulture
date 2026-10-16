export function h(req, res) {
  try { svc.load(); } catch (err) {
    // EXPECT-NEXT: clean  an opaque id derived from the error
    res.status(500).json({ id: getTraceId(err) });
  }
}
