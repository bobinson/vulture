// Feature 0101, CWE-778 Concept C (RED round 2, R2-6, R2-7). A chain whose call
// arguments break over lines (the Prettier layout) keeps its head: a security
// call opened lines above the `.catch` still makes the chain security-relevant,
// on the teardown path and on the `??` fallback path. A teardown counts only
// when it is the LAST call of the chain. Every identifier is invented.

export async function dropAllTokens(userId: string) {
  revokeAllTokens(
    userId,
  ).then(() => conn.close()).catch(() => {}); // EXPECT: finding check=cwe.insufficient_logging.promise_swallow
}

export async function dropFeed(feedId: string) {
  flushFeed(
    feedId,
  ).then(() => conn.close()).catch(() => {}); // EXPECT: clean check=cwe.insufficient_logging.promise_swallow
}

export async function whoAmI(userId: string) {
  const claims = await verifySession(
    userId,
  ).catch(() => null) ?? GUEST; // EXPECT: finding check=cwe.insufficient_logging.promise_swallow
  return claims;
}

export async function themeFor(userId: string) {
  const theme = await loadTheme(
    userId,
  ).catch(() => null) ?? DEFAULT_THEME; // EXPECT: clean check=cwe.insufficient_logging.promise_swallow
  return theme;
}

export async function warmThenRender() {
  loadCache().then(() => db.close()).then(render).catch(() => {}); // EXPECT: finding check=cwe.insufficient_logging.promise_swallow
}

export async function flushThenStop() {
  loadCache().finally(() => db.close()).catch(() => {}); // EXPECT: finding check=cwe.insufficient_logging.promise_swallow
}
