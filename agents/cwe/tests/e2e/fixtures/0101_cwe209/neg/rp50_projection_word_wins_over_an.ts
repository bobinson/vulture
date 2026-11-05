export function h(req: any, res: any) {
  try {
    run();
  } catch (err) {
    // EXPECT-NEXT: clean  projection word wins over an extractor word
    res.status(500).json({ id: getTraceId(err) });
  }
}
