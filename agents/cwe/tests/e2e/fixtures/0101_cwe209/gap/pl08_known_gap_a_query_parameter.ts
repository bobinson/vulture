export function h(req, res) {
  const url = new URL(req.url)
  const error = url.searchParams.get("error")
  // EXPECT-NEXT: finding  known-gap known-gap a query parameter named error reports through the exact-name fallback
  res.end(`failed: ${error}`)
}
