// elided.ts -- 0076 T3.3. The 0075 render joins windows with a bare "..." and
// prefixes every rendered line with "NN: ". A quote copied straight out of
// that listing must still match, so key() drops blanks and the marker.

export function connect(opts: Options) {
  const client = new Client(opts.dsn, opts.timeoutMs);


  return client.connect();
}
