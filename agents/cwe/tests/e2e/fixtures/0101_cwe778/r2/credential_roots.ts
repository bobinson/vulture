// Feature 0101, CWE-778 Concept A: credential abbreviations and auth primitives
// name a security operation. Each routine reaches the security vocabulary through
// ONE root only (sig, bearer, pw, pwd, constant-time compare); every handler hands
// its failure on and records nothing, so every one reports. Identifiers invented.

export function compareSig(given: Buffer, expected: Buffer) {
  try {
    return bytesEqual(given, expected);
  } catch (err) { // EXPECT: finding
    return toFault(err);
  }
}

export function equalBytes(a: Buffer, b: Buffer) {
  try {
    return timingSafeEqual(a, b);
  } catch (err) { // EXPECT: finding
    return toFault(err);
  }
}

export function sameBytes(a: Buffer, b: Buffer) {
  try {
    return constantTimeCompare(a, b);
  } catch (err) { // EXPECT: finding
    return toFault(err);
  }
}

export async function bindDirectory(client: Client, dn: string, pw: string) {
  try {
    await client.bind(dn, pw);
    return null;
  } catch (err) { // EXPECT: finding
    return toFault(err);
  }
}

export function parseBearer(header: string) {
  try {
    return decodeHeader(header);
  } catch (err) { // EXPECT: finding
    return toFault(err);
  }
}

export function changePwd(store: Store, oldPwd: string, newPwd: string) {
  try {
    return store.update(oldPwd, newPwd);
  } catch (err) { // EXPECT: finding
    return toFault(err);
  }
}

export function loadPinnedTabs(store: Store) {
  try {
    return store.read('tabs');
  } catch (err) { // EXPECT: clean
    return toFault(err);
  }
}
