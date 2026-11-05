try { await axios.get(u) } catch (err) {
  // EXPECT-NEXT: finding  receiver toJSON
  res.status(502).json(err.toJSON())
}
