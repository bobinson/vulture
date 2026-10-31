export function h(req, res) {
  try { run() } catch (err) {
    // EXPECT-NEXT: clean  literal under an error key
    res.status(500).json({ error: 'Try again' })
  }
}
