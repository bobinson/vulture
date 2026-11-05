export function h(req, res) {
  // EXPECT-NEXT: clean  catalog helper
  return res.status(400).json({ ...catalogEnvelope(FaultCatalog.MISSING_FIELDS) });
}
