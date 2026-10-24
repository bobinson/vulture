export function relayUpstreamFault(res: Response, err: UpstreamFetchError) {
  // EXPECT-NEXT: clean  known-gap a domain-typed error parameter is clean by design (R-C7), even when its type name ends in Error
  res.status(502).json({ message: err.message });
}
