// Known false positive (unadjudicated): `err` is the write callback's parameter
// declaration, not a value written to the peer.
export function flush(res: any, data: string) {
  res.end(data, (err) => { // EXPECT: finding known-gap callback-parameter-declaration
    if (err) metrics.count("flush_failed");
  });
}
