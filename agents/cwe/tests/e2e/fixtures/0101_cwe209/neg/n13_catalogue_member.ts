export function h(req, res) {
  try { run() } catch (err) {
    // EXPECT-NEXT: clean  catalogue member
    res.json(FaultCatalog.NOT_FOUND)
  }
}
