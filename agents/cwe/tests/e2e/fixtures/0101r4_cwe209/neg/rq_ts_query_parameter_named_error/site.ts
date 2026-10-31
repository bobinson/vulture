export function callback(req: any, res: any) {
  const callbackUrl = new URL(req.url, "http://localhost");
  const error = callbackUrl.searchParams.get("error");
  if (error) {
    res.statusCode = 400;
    res.end(`Authentication failed: ${error}`); // EXPECT: clean rq-query-parameter-named-error
  }
}
