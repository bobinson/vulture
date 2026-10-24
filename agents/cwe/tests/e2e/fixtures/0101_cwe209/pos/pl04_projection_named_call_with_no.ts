export async function h(req, res) {
  const accountRes = await loadAccountById(req.uid)
  if (!accountRes.ok) {
    // EXPECT-NEXT: finding  projection-named call with no error argument stays unknown
    return res.status(500).json({ message: accountRes.error.message })
  }
}
