export async function callback(req: any, res: any) {
  const callbackUrl = new URL(req.url, "http://localhost");
  let error = callbackUrl.searchParams.get("error");
  try {
    await exchange(callbackUrl);
  } catch (err) {
    error = String(err);
    res.end(`Authentication failed: ${error}`); // EXPECT: finding tp-rebound-from-caught
  }
}
