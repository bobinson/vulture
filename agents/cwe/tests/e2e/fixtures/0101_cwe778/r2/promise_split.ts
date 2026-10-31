// Feature 0101, CWE-778 Concept C: the chain head is read across a line break.
// A security operation on the line above, continued by a teardown and a silent
// `.catch`, still reports; a teardown-only chain split the same way is excused.

export async function logout(t: string, sock: Sock) {
  await authority.revokeRefreshToken(t)
    .then(() => sock.close()).catch(() => {}); // EXPECT: finding check=cwe.insufficient_logging.promise_swallow
}

export async function closeFeed(feed: Feed, sock: Sock) {
  await feed.flush()
    .then(() => sock.close()).catch(() => {}); // EXPECT: clean check=cwe.insufficient_logging.promise_swallow
}
