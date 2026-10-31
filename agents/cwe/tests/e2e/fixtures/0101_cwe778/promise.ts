// Feature 0101, CWE-778 Concept C: `.catch(() => <nothing>)` after a teardown call,
// or whose fallback the code null-checks, is best-effort by design, unless the chain
// head is a security operation. Invented identifiers.
export async function closeStale(stale: Conn) {
  stale.disconnect().catch(() => undefined); // EXPECT: clean check=cwe.insufficient_logging.promise_swallow
}
export async function closeLater(x: Promise<Conn>) {
  x.then(l => l.close()).catch(() => undefined); // EXPECT: clean check=cwe.insufficient_logging.promise_swallow
}
export async function readCode(r: Resp) {
  const p = await r.json().catch(() => null); // EXPECT: clean check=cwe.insufficient_logging.promise_swallow
  const c = p?.code;
  return c;
}
export async function themeOr(x: Promise<Theme>) {
  return (await x.catch(() => null)) ?? DEFAULTS; // EXPECT: clean check=cwe.insufficient_logging.promise_swallow
}

// ---- reported ----
export async function loadEvery(urls: string[]) {
  return Promise.all(urls.map((u) => getJsonFrom(u).catch(() => null))); // EXPECT: finding check=cwe.insufficient_logging.promise_swallow
}
export function loadInto(setX: Setter) {
  api.get().then(setX).catch(() => {}); // EXPECT: finding check=cwe.insufficient_logging.promise_swallow
}
export async function loadUnguarded() {
  const v = await load().catch(() => null); // EXPECT: finding check=cwe.insufficient_logging.promise_swallow
  return render(v);
}
export function lastResort() {
  // EXPECT-NEXT: finding check=cwe.insufficient_logging.promise_swallow
  process.on('unhandledRejection', () => {});
}
export async function me(t: string) {
  const claims = await verifyJwt(t).catch(() => null); // EXPECT: finding check=cwe.insufficient_logging.promise_swallow
  if (!claims) return 401;
  return claims;
}
export async function account(req: Req) {
  const s = await loadSessionFor(req).catch(() => undefined); // EXPECT: finding check=cwe.insufficient_logging.promise_swallow
  if (s == null) return 401;
  return s.user;
}
export async function logout(req: Req, id: string, t: string) {
  await revokeRefreshToken(id).finally(() => db.close()).catch(() => {}); // EXPECT: finding check=cwe.insufficient_logging.promise_swallow
  req.session.destroy().catch(() => {}); // EXPECT: finding check=cwe.insufficient_logging.promise_swallow
  await revokeToken(t).then(() => session.destroy()).catch(() => {}); // EXPECT: finding check=cwe.insufficient_logging.promise_swallow
}
