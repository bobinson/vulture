app.get("/x", async (req, res) => {
  try { await run() } catch (err) {
    // EXPECT-NEXT: finding
    res.status(500).json(serializeFault(err))
  }
})
