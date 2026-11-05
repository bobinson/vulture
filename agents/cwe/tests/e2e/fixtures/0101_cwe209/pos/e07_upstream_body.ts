try { await axios.get(u) } catch (err) {
  // EXPECT-NEXT: finding  upstream body
  res.status(502).json({ details: err.response.data })
}
