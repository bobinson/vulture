export function h(req, res) {
  const url = new URL(req.url)
  const error = url.searchParams.get("error")
  // EXPECT-NEXT: clean  a query parameter named error is request data, not an exception (rev4)
  res.end(`failed: ${error}`)
}
