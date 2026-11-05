export function readSettings(req, res) {
  const { value, error } = parseSettingsBlob(req.body.blob);
  // EXPECT-NEXT: finding  destructured from a call result without await
  if (error) return res.status(400).json({ reason: error.message });
  res.json(value);
}
